"""Incident management service for queries, status updates, and evidence analysis."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session
from app.analysis.llm_analyzer import LLMIncidentAnalyzer
from app.config import IncidentStatus
from app.models.alert import AlertModel
from app.models.incident import (
    IncidentAlertModel,
    IncidentModel,
    IncidentStatusHistoryModel,
)
from app.models.summary import IncidentEvidenceSummaryModel


class IncidentService:
    """Service handling incident business logic, triage transitions, and evidence."""

    @staticmethod
    def get_incident(db: Session, incident_id: str) -> Optional[IncidentModel]:
        """Fetch incident by unique identifier."""
        stmt = select(IncidentModel).where(IncidentModel.id == incident_id)
        return db.execute(stmt).scalars().first()

    @staticmethod
    def list_incidents(
        db: Session,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[IncidentModel], int]:
        """List incidents with multi-attribute filtering and pagination."""
        stmt = select(IncidentModel)
        count_stmt = select(func.count(IncidentModel.id))

        if status:
            stmt = stmt.where(IncidentModel.status == status.upper())
            count_stmt = count_stmt.where(IncidentModel.status == status.upper())
        if priority:
            stmt = stmt.where(IncidentModel.priority == priority.upper())
            count_stmt = count_stmt.where(IncidentModel.priority == priority.upper())
        if search:
            pattern = f"%{search}%"
            search_clause = or_(
                IncidentModel.id.ilike(pattern),
                IncidentModel.title.ilike(pattern),
                IncidentModel.primary_host.ilike(pattern),
                IncidentModel.primary_user.ilike(pattern),
            )
            stmt = stmt.where(search_clause)
            count_stmt = count_stmt.where(search_clause)

        total = db.execute(count_stmt).scalar() or 0
        items = db.execute(
            stmt.order_by(desc(IncidentModel.score), desc(IncidentModel.updated_at))
            .limit(limit)
            .offset(offset)
        ).scalars().all()

        return list(items), total

    @classmethod
    def update_status(
        cls,
        db: Session,
        incident_id: str,
        new_status: IncidentStatus,
        notes: str = "",
        analyst: str = "soc_analyst",
    ) -> Optional[IncidentModel]:
        """Update incident status and append an immutable audit log entry."""
        incident = cls.get_incident(db, incident_id)
        if not incident:
            return None

        old_status = incident.status
        incident.status = new_status.value
        incident.updated_at = datetime.now(timezone.utc)

        # Record audit history
        history = IncidentStatusHistoryModel(
            incident_id=incident.id,
            old_status=old_status,
            new_status=new_status.value,
            notes=notes,
            changed_by=analyst,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(history)
        db.commit()
        db.refresh(incident)
        return incident

    @classmethod
    def generate_or_update_summary(
        cls,
        db: Session,
        incident_id: str,
        use_llm: bool = False,
    ) -> Optional[IncidentEvidenceSummaryModel]:
        """Generate factual evidence synthesis and persist in the database."""
        incident = cls.get_incident(db, incident_id)
        if not incident:
            return None

        # Fetch associated alerts
        alerts = [l.alert for l in incident.alert_links if l.alert]

        analysis = LLMIncidentAnalyzer.analyze_incident(incident, alerts, use_llm=use_llm)

        summary_model = IncidentEvidenceSummaryModel(
            incident_id=incident.id,
            summary_type="LLM_ASSISTED" if use_llm else "DETERMINISTIC",
            concise_summary=analysis.concise_summary,
            observed_facts=analysis.observed_facts,
            inferred_hypotheses=analysis.inferred_hypotheses,
            chronological_timeline=[t.model_dump(mode="json") for t in analysis.chronological_timeline],
            recommended_actions=analysis.recommended_actions,
            is_validated=analysis.is_validated,
            generated_at=datetime.now(timezone.utc),
        )
        db.add(summary_model)
        db.commit()
        db.refresh(summary_model)
        return summary_model
