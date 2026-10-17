"""SQLAlchemy ORM model for Alerts."""

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
    Index,
)
from sqlalchemy.orm import relationship
from app.database import Base


class AlertModel(Base):
    """Normalized security alert record in the database."""

    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_event_id = Column(String(255), nullable=False, index=True)
    source = Column(String(100), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    ingested_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=0.5)

    user_entity = Column(String(255), nullable=True, index=True)
    host_entity = Column(String(255), nullable=True, index=True)
    asset_criticality = Column(String(30), nullable=False, default="MEDIUM")

    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True)

    indicators = Column(JSON, nullable=False, default=list)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False, default="")
    
    # Forensic unaltered original payload
    raw_payload = Column(JSON, nullable=False, default=dict)

    # Cryptographic deduplication hash
    deduplication_hash = Column(String(64), unique=True, nullable=False, index=True)

    # Relationships
    incident_links = relationship("IncidentAlertModel", back_populates="alert", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_alert_host_user_ts", "host_entity", "user_entity", "timestamp"),
        Index("idx_alert_source_event", "source", "source_event_id"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "source_event_id": self.source_event_id,
            "source": self.source,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "ingested_at": self.ingested_at.isoformat() if self.ingested_at else None,
            "event_type": self.event_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "user_entity": self.user_entity,
            "host_entity": self.host_entity,
            "asset_criticality": self.asset_criticality,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "indicators": self.indicators or [],
            "title": self.title,
            "description": self.description,
            "raw_payload": self.raw_payload or {},
            "deduplication_hash": self.deduplication_hash,
        }
