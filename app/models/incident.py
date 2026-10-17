"""SQLAlchemy ORM models for Incidents, links, and status history."""

from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import (
    Column,
    String,
    Float,
    Integer,
    DateTime,
    JSON,
    Text,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from app.database import Base


class IncidentModel(Base):
    """Correlated security incident record."""

    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    title = Column(String(500), nullable=False)
    status = Column(String(30), nullable=False, default="NEW", index=True)
    priority = Column(String(30), nullable=False, default="MEDIUM", index=True)
    score = Column(Float, nullable=False, default=0.0)
    score_breakdown = Column(JSON, nullable=False, default=list)

    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    first_seen = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, nullable=False, index=True)

    primary_user = Column(String(255), nullable=True, index=True)
    primary_host = Column(String(255), nullable=True, index=True)
    correlated_indicators = Column(JSON, nullable=False, default=list)
    alert_count = Column(Integer, nullable=False, default=0)

    # Relationships
    alert_links = relationship("IncidentAlertModel", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentAlertModel.linked_at")
    evidence_summaries = relationship("IncidentEvidenceSummaryModel", back_populates="incident", cascade="all, delete-orphan", order_by="desc(IncidentEvidenceSummaryModel.generated_at)")
    status_history = relationship("IncidentStatusHistoryModel", back_populates="incident", cascade="all, delete-orphan", order_by="IncidentStatusHistoryModel.timestamp")

    __table_args__ = (
        Index("idx_incident_status_prio", "status", "priority"),
        Index("idx_incident_host_user", "primary_host", "primary_user"),
    )


class IncidentAlertModel(Base):
    """Link table between Incidents and Alerts with correlation rationale."""

    __tablename__ = "incident_alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    correlation_reason = Column(String(100), nullable=False, default="CORRELATED")
    linked_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    incident = relationship("IncidentModel", back_populates="alert_links")
    alert = relationship("AlertModel", back_populates="incident_links")

    __table_args__ = (
        Index("idx_inc_alert_unique", "incident_id", "alert_id", unique=True),
    )


class IncidentStatusHistoryModel(Base):
    """Audit log of incident lifecycle transitions."""

    __tablename__ = "incident_status_history"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    old_status = Column(String(30), nullable=False)
    new_status = Column(String(30), nullable=False)
    notes = Column(Text, nullable=False, default="")
    changed_by = Column(String(100), nullable=False, default="system")
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    incident = relationship("IncidentModel", back_populates="status_history")
