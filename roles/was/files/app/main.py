import os
import secrets
import jwt
import requests
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from urllib.parse import urlencode

from sqlalchemy import create_engine, text

# ======================================================
# App
# ======================================================
app = FastAPI(title="Auth Server", version="1.0")

# ======================================================
# Environment Variables
# ======================================================
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

# ======================================================
# Google OAuth URLs
# ======================================================
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# ======================================================
# DB Engine (DB 설정 없으면 engine 생성 안 함)
# ======================================================
engine = None
if DB_HOST and DB_NAME and DB_USER and DB_PASSWORD:
    DB_URL = (
        f"postgresql://{DB_USER}:{DB_PASSWORD}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    engine = create_engine(DB_URL, pool_pre_ping=True)

# ======================================================
# Temporary CSRF State Store
# (실서비스: Redis 권장)
# ======================================================
STATE_STORE = {}

# ======================================================
# Health
# ======================================================
@app.get("/")
def root():
    return {"message": "Auth server is running"}

@app.get("/health")
def health():
    return {"status": "ok", "db_configured": engine is not None}

# ======================================================
# 1. Google Login
# ======================================================
@app.get("/auth/google/login")
def google_login():
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET or not GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status_code=500,
            detail="Google OAuth environment variables are not configured",
        )

    state = secrets.token_urlsafe(16)
    STATE_STORE[state] = True

    scope = (
        "openid email profile "
        "https://www.googleapis.com/auth/youtube.upload"
    )

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": scope,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }

    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return RedirectResponse(auth_url)

# ======================================================
# 2. Google Callback
# ======================================================
@app.get("/auth/callback")
def google_callback(
    code: Optional[str] = None,
    state: Optional[str] = None,
):
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    if state not in STATE_STORE:
        raise HTTPException(status_code=400, detail="Invalid or expired CSRF state")

    del STATE_STORE[state]

    # ==================================================
    # 3. Google Token Exchange
    # ==================================================
    token_resp = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GOOGLE_REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=5,
    )

    if token_resp.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail=f"Google token exchange failed: {token_resp.text}",
        )

    token_data = token_resp.json()
    google_access_token = token_data.get("access_token")
    google_refresh_token = token_data.get("refresh_token")

    if not google_access_token:
        raise HTTPException(status_code=400, detail="No access token from Google")

    # ==================================================
    # 4. Google User Info
    # ==================================================
    userinfo_resp = requests.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {google_access_token}"},
        timeout=5,
    )

    if userinfo_resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch user info")

    userinfo = userinfo_resp.json()
    google_id = userinfo.get("id")
    email = userinfo.get("email")

    if not google_id or not email:
        raise HTTPException(status_code=400, detail="Invalid user info")

    # ==================================================
    # 5. DB Mapping (핵심)
    # ==================================================
    if engine is None:
        raise HTTPException(status_code=503, detail="DB is not configured")

    with engine.begin() as conn:

        # 1️⃣ 사용자 존재 여부 확인
        result = conn.execute(
            text("SELECT id FROM users WHERE google_id = :gid"),
            {"gid": google_id},
        ).fetchone()

        if result:
            user_db_id = result.id

            # 마지막 로그인 시각 갱신
            conn.execute(
                text("UPDATE users SET updated_at = NOW() WHERE id = :id"),
                {"id": user_db_id},
            )

        else:
            # 2️⃣ 최초 로그인 → 사용자 생성
            result = conn.execute(
                text("""
                    INSERT INTO users (google_id, email)
                    VALUES (:gid, :email)
                    RETURNING id
                """),
                {"gid": google_id, "email": email},
            )
            user_db_id = result.fetchone().id

        # 3️⃣ refresh_token 저장 (있을 때만)
        if google_refresh_token:
            conn.execute(
                text("""
                    INSERT INTO oauth_tokens (user_id, provider, refresh_token)
                    VALUES (:uid, 'google', :rt)
                    ON CONFLICT (user_id, provider)
                    DO UPDATE SET
                        refresh_token = EXCLUDED.refresh_token,
                        created_at = NOW()
                """),
                {"uid": user_db_id, "rt": google_refresh_token},
            )

    # ==================================================
    # 6. JWT Issuance (내부 사용자 기준)
    # ==================================================
    now = datetime.utcnow()
    payload = {
        "sub": str(user_db_id),
        "email": email,
        "iss": "onprem-auth-server",
        "aud": "onprem-video-platform",
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }

    jwt_token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return JSONResponse(
        {
            "access_token": jwt_token,
            "token_type": "bearer",
            "expires_in": JWT_EXPIRE_MINUTES * 60,
        }
    )
