from fastapi import FastAPI
from models.database import init_db
from routers.auth_router      import router as auth_router
from routers.users_router     import router as users_router
from routers.apps_router      import router as apps_router
from routers.providers_router import router as providers_router

app = FastAPI(
    title="AccessNex API",
    description="Multi-Factor Physical Access Control System — Backend API",
    version="1.0.0",
)

# Initialize database tables on startup
@app.on_event("startup")
def on_startup():
    init_db()

# Register routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(apps_router)
app.include_router(providers_router)


@app.get("/", tags=["Health"])
def root():
    return {"message": "AccessNex API is running", "version": "1.0.0"}
