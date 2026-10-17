"""Health and metrics API router."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.config import IncidentStatus, settings
from app.database import get_db
from app.models.alert import AlertModel
from app.models.incident import IncidentModel

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """System health and operational telemetry."""
    status: str
    app_name: str
    timestamp: datetime
    database_connected: bool
    total_alerts: int
    total_incidents: int
    active_incidents: int


@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)):
    """Health check verifying database operational readiness and core metrics."""
    db_ok = True
    total_alerts = 0
    total_incidents = 0
    active_incidents = 0

    try:
        total_alerts = db.execute(select(func.count(AlertModel.id))).scalar() or 0
        total_incidents = db.execute(select(func.count(IncidentModel.id))).scalar() or 0
        active_incidents = (
            db.execute(
                select(func.count(IncidentModel.id)).where(
                    IncidentModel.status.in_([
                        IncidentStatus.NEW.value,
                        IncidentStatus.TRIAGED.value,
                        IncidentStatus.INVESTIGATING.value,
                    ])
                )
            ).scalar()
            or 0
        )
    except Exception:
        db_ok = False

    return HealthResponse(
        status="healthy" if db_ok else "degraded",
        app_name=settings.APP_NAME,
        timestamp=datetime.now(timezone.utc),
        database_connected=db_ok,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
        active_incidents=active_incidents,
    )
