"""SQLAlchemy ORM model for grounded incident evidence summaries."""

from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    JSON,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from app.database import Base


class IncidentEvidenceSummaryModel(Base):
    """Factual, grounded incident summary and timeline."""

    __tablename__ = "incident_evidence_summaries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    summary_type = Column(String(50), nullable=False, default="DETERMINISTIC")  # "DETERMINISTIC" or "LLM_ASSISTED"
    concise_summary = Column(Text, nullable=False)
    
    # Strictly separated factual evidence vs inferences
    observed_facts = Column(JSON, nullable=False, default=list)
    inferred_hypotheses = Column(JSON, nullable=False, default=list)
    chronological_timeline = Column(JSON, nullable=False, default=list)
    recommended_actions = Column(JSON, nullable=False, default=list)

    is_validated = Column(Boolean, nullable=False, default=True)
    generated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    incident = relationship("IncidentModel", back_populates="evidence_summaries")
