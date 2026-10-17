"""Event Correlation Engine for clustering related security alerts into incidents."""

from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple
from uuid import uuid4
import logging
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.config import IncidentStatus, settings
from app.correlation.rules import evaluate_alert_correlation
from app.models.alert import AlertModel
from app.models.incident import (
    IncidentAlertModel,
    IncidentModel,
    IncidentStatusHistoryModel,
)
from app.scoring.engine import ScoringEngine

logger = logging.getLogger("security_triage.correlation")


class CorrelationEngine:
    """Clusters security alerts into explainable incidents based on configurable rules."""

    @classmethod
    def get_active_incidents(cls, db: Session) -> List[IncidentModel]:
        """Fetch open incidents eligible for correlation."""
        stmt = (
            select(IncidentModel)
            .where(
                IncidentModel.status.in_([
                    IncidentStatus.NEW.value,
                    IncidentStatus.TRIAGED.value,
                    IncidentStatus.INVESTIGATING.value,
                ])
            )
            .order_by(IncidentModel.last_seen.desc())
        )
        return list(db.execute(stmt).scalars().all())

    @classmethod
    def find_matching_incident(
        cls,
        active_incidents: List[IncidentModel],
        alert: AlertModel,
        window_minutes: int,
    ) -> Optional[Tuple[IncidentModel, str]]:
        """Find the most relevant active incident that correlates with the alert."""
        for inc in active_incidents:
            reason = evaluate_alert_correlation(alert, inc, window_minutes)
            if reason:
                return inc, reason
        return None

    @classmethod
    def correlate_alert(
        cls,
        db: Session,
        alert: AlertModel,
        window_minutes: Optional[int] = None,
    ) -> Tuple[IncidentModel, bool]:
        """Correlate a single alert into an existing incident or create a new one.
        
        Returns (IncidentModel, is_new_incident).
        """
        # Check if alert is already linked to an incident
        existing_link = (
            db.execute(
                select(IncidentAlertModel).where(IncidentAlertModel.alert_id == alert.id)
            )
            .scalars()
            .first()
        )
        if existing_link:
            incident = db.execute(
                select(IncidentModel).where(IncidentModel.id == existing_link.incident_id)
            ).scalars().first()
            if incident:
                return incident, False

        window = window_minutes if window_minutes is not None else settings.CORRELATION_WINDOW_MINUTES
        active_incidents = cls.get_active_incidents(db)
        match = cls.find_matching_incident(active_incidents, alert, window)

        if match:
            incident, reason = match
            logger.info("Correlating alert %s with incident %s (%s)", alert.id, incident.id, reason)

            # Link alert to existing incident
            link = IncidentAlertModel(
                incident_id=incident.id,
                alert_id=alert.id,
                correlation_reason=reason,
                linked_at=datetime.now(timezone.utc),
            )
            db.add(link)

            # Update incident time bounds
            if alert.timestamp < incident.first_seen:
                incident.first_seen = alert.timestamp
            if alert.timestamp > incident.last_seen:
                incident.last_seen = alert.timestamp

            # Aggregate IOCs
            current_iocs = set(incident.correlated_indicators or [])
            if alert.indicators:
                current_iocs.update(alert.indicators)
            incident.correlated_indicators = sorted(list(current_iocs))

            # Update primary entities if incident lacked them
            if not incident.primary_host and alert.host_entity:
                incident.primary_host = alert.host_entity
            if not incident.primary_user and alert.user_entity:
                incident.primary_user = alert.user_entity

            # Fetch all currently linked alerts to recalculate score
            all_alerts = [l.alert for l in incident.alert_links if l.alert]
            if alert not in all_alerts:
                all_alerts.append(alert)

            incident.alert_count = len(all_alerts)
            scoring_res = ScoringEngine.evaluate_incident(all_alerts)
            incident.score = scoring_res.score
            incident.priority = scoring_res.priority.value
            incident.score_breakdown = [f.model_dump() for f in scoring_res.factors]
            incident.updated_at = datetime.now(timezone.utc)

            db.commit()
            db.refresh(incident)
            return incident, False

        else:
            # Create a brand new incident
            logger.info("Creating new incident for alert %s (%s)", alert.id, alert.title)
            inc_id = f"INC-{datetime.now(timezone.utc).year}-{uuid4().hex[:6].upper()}"
            entity_label = alert.host_entity or alert.user_entity or "Host"
            title = f"{alert.event_type} on {entity_label}"

            initial_iocs = sorted(list(set(alert.indicators or [])))
            scoring_res = ScoringEngine.evaluate_incident([alert])

            new_incident = IncidentModel(
                id=inc_id,
                title=title,
                status=IncidentStatus.NEW.value,
                priority=scoring_res.priority.value,
                score=scoring_res.score,
                score_breakdown=[f.model_dump() for f in scoring_res.factors],
                first_seen=alert.timestamp,
                last_seen=alert.timestamp,
                primary_user=alert.user_entity,
                primary_host=alert.host_entity,
                correlated_indicators=initial_iocs,
                alert_count=1,
            )
            db.add(new_incident)
            db.flush()

            # Create link
            link = IncidentAlertModel(
                incident_id=new_incident.id,
                alert_id=alert.id,
                correlation_reason="INITIAL_TRIGGER",
                linked_at=datetime.now(timezone.utc),
            )
            db.add(link)

            # Add status history
            history = IncidentStatusHistoryModel(
                incident_id=new_incident.id,
                old_status="NONE",
                new_status=IncidentStatus.NEW.value,
                notes=f"Incident opened automatically by alert {alert.source_event_id}.",
                changed_by="correlation_engine",
            )
            db.add(history)

            db.commit()
            db.refresh(new_incident)
            return new_incident, True

    @classmethod
    def correlate_batch(
        cls,
        db: Session,
        alerts: List[AlertModel],
        window_minutes: Optional[int] = None,
    ) -> Tuple[List[str], List[str]]:
        """Correlate a list of newly ingested alerts in chronological order.
        
        Returns (created_incident_ids, updated_incident_ids).
        """
        created_ids: Set[str] = set()
        updated_ids: Set[str] = set()

        # Sort alerts chronologically so event sequence is correlated naturally
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)

        for alert in sorted_alerts:
            incident, is_new = cls.correlate_alert(db, alert, window_minutes)
            if is_new:
                created_ids.add(incident.id)
            else:
                updated_ids.add(incident.id)

        return sorted(list(created_ids)), sorted(list(updated_ids))
