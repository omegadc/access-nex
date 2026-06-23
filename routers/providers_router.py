from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional

from models.database import ProviderDB, get_db
from routers.auth_router import require_admin

router = APIRouter(prefix="/providers", tags=["Provider Management"])

VALID_PROTOCOLS = {"OIDC", "OAuth2", "SAML"}


# ── Schemas ──────────────────────────────────────────────────────────────────

class ProviderCreate(BaseModel):
    name:          str
    protocol:      str          # "OIDC" | "OAuth2" | "SAML"
    client_id:     Optional[str] = None
    client_secret: Optional[str] = None
    metadata_url:  Optional[str] = None

class ProviderUpdate(BaseModel):
    name:          Optional[str] = None
    client_id:     Optional[str] = None
    client_secret: Optional[str] = None
    metadata_url:  Optional[str] = None
    is_active:     Optional[bool] = None

class ProviderResponse(BaseModel):
    id:           int
    name:         str
    protocol:     str
    client_id:    Optional[str]
    metadata_url: Optional[str]
    is_active:    bool
    # client_secret intentionally omitted from responses

    class Config:
        from_attributes = True


# ── GET /providers ────────────────────────────────────────────────────────────

@router.get("/", response_model=List[ProviderResponse], summary="List all identity providers")
def list_providers(
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    return db.query(ProviderDB).all()


# ── GET /providers/{provider_id} ──────────────────────────────────────────────

@router.get("/{provider_id}", response_model=ProviderResponse, summary="Get a provider by ID")
def get_provider(
    provider_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    provider = db.query(ProviderDB).filter(ProviderDB.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    return provider


# ── POST /providers ───────────────────────────────────────────────────────────
# Register a new identity provider (e.g. Keycloak, Auth0, Okta).

@router.post("/", response_model=ProviderResponse, status_code=status.HTTP_201_CREATED, summary="Register a new identity provider")
def create_provider(
    payload: ProviderCreate,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    if payload.protocol not in VALID_PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"Protocol must be one of: {', '.join(VALID_PROTOCOLS)}")
    if db.query(ProviderDB).filter(ProviderDB.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Provider name already exists")

    provider = ProviderDB(
        name=payload.name,
        protocol=payload.protocol,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        metadata_url=payload.metadata_url,
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return provider


# ── PUT /providers/{provider_id} ──────────────────────────────────────────────

@router.put("/{provider_id}", response_model=ProviderResponse, summary="Update a provider")
def update_provider(
    provider_id: int,
    payload: ProviderUpdate,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    provider = db.query(ProviderDB).filter(ProviderDB.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    if payload.name          is not None: provider.name          = payload.name
    if payload.client_id     is not None: provider.client_id     = payload.client_id
    if payload.client_secret is not None: provider.client_secret = payload.client_secret
    if payload.metadata_url  is not None: provider.metadata_url  = payload.metadata_url
    if payload.is_active     is not None: provider.is_active     = payload.is_active

    db.commit()
    db.refresh(provider)
    return provider


# ── DELETE /providers/{provider_id} ───────────────────────────────────────────

@router.delete("/{provider_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a provider")
def delete_provider(
    provider_id: int,
    db: Session = Depends(get_db),
    _: dict = Depends(require_admin),
):
    provider = db.query(ProviderDB).filter(ProviderDB.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    db.delete(provider)
    db.commit()
