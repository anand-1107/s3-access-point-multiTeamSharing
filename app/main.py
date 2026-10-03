import logging
from fastapi import FastAPI
from app.config import get_settings
from app.routers.teams import router as teams_router
from app.routers.users import router as users_router
from app.routers.access import router as access_router
from app.services.team_service import TeamService
from app.services.user_service import UserService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
settings = get_settings()
app = FastAPI(title="S3 Access Manager", version="1.0.0", description="Automated team-based AWS S3 access control. Defaults to policy-only dry-run mode.")
app.state.team_service = TeamService(settings)
app.state.user_service = UserService(settings, team_service=app.state.team_service)
app.state.team_service.user_service = app.state.user_service
app.include_router(teams_router)
app.include_router(users_router)
app.include_router(access_router)


@app.get("/", tags=["system"], summary="Service information", include_in_schema=False)
def root():
    return {"name": "S3 Access Manager", "version": app.version, "dry_run": settings.dry_run, "docs": "/docs"}


@app.get("/health", tags=["system"], summary="Health check", include_in_schema=False)
def health():
    return {"status": "ok", "dry_run": settings.dry_run}
