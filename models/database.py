from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

DATABASE_URL = "sqlite:///./accessnex.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Database Models ──────────────────────────────────────────────────────────

class UserDB(Base):
    __tablename__ = "users"
    id          = Column(Integer, primary_key=True, index=True)
    username    = Column(String, unique=True, index=True, nullable=False)
    email       = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role        = Column(String, default="user")   # "admin" | "user"
    is_active   = Column(Boolean, default=True)


class AppDB(Base):
    __tablename__ = "apps"
    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    client_id   = Column(String, unique=True, nullable=False)
    is_active   = Column(Boolean, default=True)


class ProviderDB(Base):
    __tablename__ = "providers"
    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String, unique=True, nullable=False)
    protocol    = Column(String, nullable=False)   # e.g. "OIDC", "SAML", "OAuth2"
    client_id   = Column(String, nullable=True)
    client_secret = Column(String, nullable=True)
    metadata_url  = Column(String, nullable=True)
    is_active   = Column(Boolean, default=True)


def get_db():
    """FastAPI dependency — yields a DB session, closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
