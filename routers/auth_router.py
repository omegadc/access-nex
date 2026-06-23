from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from models.database import get_db
from models.auth import (
    authenticate_user_json,
    authenticate_user_db,
    create_access_token,
    decode_token,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ── Schemas ──────────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


# ── Dependency: get current user from JWT ────────────────────────────────────

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload   # dict with at least {"sub": username, "role": role}

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only")
    return current_user


# ── POST /auth/login ─────────────────────────────────────────────────────────
# Accepts standard OAuth2 form (username + password).
# Phase 1 → validates against users.json
# Phase 2 → falls back to SQL DB if JSON auth fails

@router.post("/login", response_model=Token, summary="Login and receive a JWT")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    # Phase 1: try JSON store
    user = authenticate_user_json(form_data.username, form_data.password)
    role = user["role"] if user else None

    # Phase 2: fall back to database
    if user is None:
        db_user = authenticate_user_db(db, form_data.username, form_data.password)
        if db_user:
            role = db_user.role
            user = {"username": db_user.username}

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": form_data.username, "role": role})
    return {"access_token": token, "token_type": "bearer"}


# ── GET /auth/me ─────────────────────────────────────────────────────────────

@router.get("/me", summary="Return the currently authenticated user")
def me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user.get("sub"), "role": current_user.get("role")}
