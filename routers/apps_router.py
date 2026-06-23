import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional

from models.database import AppDB, get_db
from routers.auth_router import require_admin

router = APIRouter(prefix="/apps", tags=["App Management"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class AppCreate(BaseModel):
    name:        str
    description: Optional[str] = None

class AppUpdate(BaseModel):
    name:        Optional[str] = None
    description: Optional[str] = None
    is_active:   Optional[bool] = None

class AppResponse(BaseModel):
    id:          int
    name:        str
    description: Optional[str]
    client_id:   str
    is_active:   bool

    class Config:
        from_attributes = True


# ── GET /apps ─────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[AppResponse], summary="List all registered apps")
def list_apps(
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    return db.query(AppDB).all()


# ── GET /apps/{app_id} ────────────────────────────────────────────────────────

@router.get("/{app_id}", response_model=AppResponse, summary="Get an app by ID")
def get_app(
    app_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    app = db.query(AppDB).filter(AppDB.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    return app


# ── POST /apps ────────────────────────────────────────────────────────────────
# Registers a new application and auto-generates a client_id.

@router.post("/", response_model=AppResponse, status_code=status.HTTP_201_CREATED, summary="Register a new app")
def create_app(
    payload: AppCreate,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    if db.query(AppDB).filter(AppDB.name == payload.name).first():
        raise HTTPException(status_code=400, detail="App name already exists")

    app = AppDB(
        name=payload.name,
        description=payload.description,
        client_id=str(uuid.uuid4()),
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app


# ── PUT /apps/{app_id} ────────────────────────────────────────────────────────

@router.put("/{app_id}", response_model=AppResponse, summary="Update an app")
def update_app(
    app_id: int,
    payload: AppUpdate,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    app = db.query(AppDB).filter(AppDB.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")

    if payload.name        is not None: app.name        = payload.name
    if payload.description is not None: app.description = payload.description
    if payload.is_active   is not None: app.is_active   = payload.is_active

    db.commit()
    db.refresh(app)
    return app


# ── DELETE /apps/{app_id} ─────────────────────────────────────────────────────

@router.delete("/{app_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete an app")
def delete_app(
    app_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    app = db.query(AppDB).filter(AppDB.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    db.delete(app)
    db.commit()
