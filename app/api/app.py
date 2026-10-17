"""FastAPI application factory and middleware configuration."""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.routes import alerts, health, incidents
from app.config import settings
from app.database import init_db

logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("security_triage.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables on application startup."""
    logger.info("Initializing database schema for %s...", settings.APP_NAME)
    init_db()
    logger.info("Database schema successfully initialized.")
    yield
    logger.info("Application shutting down.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.APP_NAME,
        version="1.0.0",
        description=(
            "Security Alert Triage and Incident Analysis REST API. "
            "Ingests alerts, performs correlation and explainable deterministic scoring, "
            "and generates grounded incident summaries."
        ),
        lifespan=lifespan,
    )

    # CORS configuration for analyst web frontends
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global unhandled exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled API exception on %s: %s", request.url.path, str(exc), exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "InternalServerError",
                "message": "An unexpected error occurred during processing. Telemetry logged.",
            },
        )

    # Mount API routers under /api/v1
    app.include_router(alerts.router, prefix="/api/v1")
    app.include_router(incidents.router, prefix="/api/v1")
    app.include_router(health.router, prefix="/api/v1")

    @app.get("/", include_in_schema=False)
    def root():
        return {
            "name": settings.APP_NAME,
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/api/v1/health",
        }

    return app


app = create_app()
