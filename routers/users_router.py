from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import List, Optional

from models.database import UserDB, get_db
from models.auth import hash_password
from routers.auth_router import require_admin

router = APIRouter(prefix="/users", tags=["User Management"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username:  str
    email:     str
    password:  str
    role:      Optional[str] = "user"

class UserUpdate(BaseModel):
    email:     Optional[str] = None
    role:      Optional[str] = None
    is_active: Optional[bool] = None

class UserResponse(BaseModel):
    id:        int
    username:  str
    email:     str
    role:      str
    is_active: bool

    class Config:
        from_attributes = True


# ── GET /users ────────────────────────────────────────────────────────────────
# Returns a list of all users. Admin only.

@router.get("/", response_model=List[UserResponse], summary="List all users")
def list_users(
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    return db.query(UserDB).all()


# ── GET /users/{user_id} ──────────────────────────────────────────────────────

@router.get("/{user_id}", response_model=UserResponse, summary="Get a user by ID")
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# ── POST /users ───────────────────────────────────────────────────────────────
# Create a new user. Admin only.

@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED, summary="Create a new user")
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    if db.query(UserDB).filter(UserDB.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(UserDB).filter(UserDB.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = UserDB(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# ── PUT /users/{user_id} ──────────────────────────────────────────────────────
# Update an existing user's email, role, or active status. Admin only.

@router.put("/{user_id}", response_model=UserResponse, summary="Update a user")
def update_user(
    user_id: int,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.email     is not None: user.email     = payload.email
    if payload.role      is not None: user.role      = payload.role
    if payload.is_active is not None: user.is_active = payload.is_active

    db.commit()
    db.refresh(user)
    return user


# ── DELETE /users/{user_id} ───────────────────────────────────────────────────

@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a user")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
