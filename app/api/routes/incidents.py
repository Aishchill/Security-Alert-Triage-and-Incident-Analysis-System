"""FastAPI router for incident triage, queries, and evidence summaries."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.schemas.alert import AlertRead
from app.schemas.incident import (
    EvidenceSummaryRead,
    IncidentAlertLinkRead,
    IncidentDetailRead,
    IncidentRead,
    IncidentStatusHistoryRead,
    IncidentStatusUpdate,
    PaginatedResponse,
)
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


class AnalyzeRequest(BaseModel):
    """Payload to trigger incident analysis."""
    use_llm: bool = False


@router.get("", response_model=PaginatedResponse[IncidentRead])
def list_incidents(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List security incidents with filtering and pagination."""
    items, total = IncidentService.list_incidents(
        db, status=status, priority=priority, search=search, limit=limit, offset=offset
    )

    results = []
    for inc in items:
        results.append(
            IncidentRead(
                id=inc.id,
                title=inc.title,
                status=inc.status,
                priority=inc.priority,
                score=inc.score,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                first_seen=inc.first_seen,
                last_seen=inc.last_seen,
                primary_user=inc.primary_user,
                primary_host=inc.primary_host,
                correlated_indicators=inc.correlated_indicators or [],
                alert_count=inc.alert_count,
            )
        )

    return PaginatedResponse(items=results, total=total, limit=limit, offset=offset)


@router.get("/{incident_id}", response_model=IncidentDetailRead)
def get_incident_detail(incident_id: str, db: Session = Depends(get_db)):
    """Retrieve full incident details including linked alerts, score explanation, and evidence."""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )

    # Automatically generate baseline evidence summary if none exists yet
    latest_summary = None
    if incident.evidence_summaries:
        latest_summary = incident.evidence_summaries[0]
    else:
        latest_summary = IncidentService.generate_or_update_summary(db, incident.id, use_llm=False)

    # Format linked alerts
    alerts_read = []
    links_read = []
    for link in incident.alert_links:
        alert = link.alert
        if alert:
            a_read = AlertRead(
                id=alert.id,
                source_event_id=alert.source_event_id,
                source=alert.source,
                timestamp=alert.timestamp,
                ingested_at=alert.ingested_at,
                event_type=alert.event_type,
                severity=alert.severity,
                confidence=alert.confidence,
                user_entity=alert.user_entity,
                host_entity=alert.host_entity,
                asset_criticality=alert.asset_criticality,
                source_ip=alert.source_ip,
                destination_ip=alert.destination_ip,
                destination_port=alert.destination_port,
                indicators=alert.indicators or [],
                title=alert.title,
                description=alert.description,
                deduplication_hash=alert.deduplication_hash,
                incident_id=incident.id,
            )
            alerts_read.append(a_read)
            links_read.append(
                IncidentAlertLinkRead(
                    id=link.id,
                    incident_id=link.incident_id,
                    alert_id=link.alert_id,
                    correlation_reason=link.correlation_reason,
                    linked_at=link.linked_at,
                    alert=a_read,
                )
            )

    history_read = [
        IncidentStatusHistoryRead(
            id=h.id,
            incident_id=h.incident_id,
            old_status=h.old_status,
            new_status=h.new_status,
            notes=h.notes,
            changed_by=h.changed_by,
            timestamp=h.timestamp,
        )
        for h in incident.status_history
    ]

    summary_read = (
        EvidenceSummaryRead(
            id=latest_summary.id,
            incident_id=latest_summary.incident_id,
            summary_type=latest_summary.summary_type,
            concise_summary=latest_summary.concise_summary,
            observed_facts=latest_summary.observed_facts or [],
            inferred_hypotheses=latest_summary.inferred_hypotheses or [],
            chronological_timeline=latest_summary.chronological_timeline or [],
            recommended_actions=latest_summary.recommended_actions or [],
            is_validated=latest_summary.is_validated,
            generated_at=latest_summary.generated_at,
        )
        if latest_summary
        else None
    )

    return IncidentDetailRead(
        id=incident.id,
        title=incident.title,
        status=incident.status,
        priority=incident.priority,
        score=incident.score,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        primary_user=incident.primary_user,
        primary_host=incident.primary_host,
        correlated_indicators=incident.correlated_indicators or [],
        alert_count=incident.alert_count,
        score_breakdown=incident.score_breakdown or [],
        alerts=alerts_read,
        alert_links=links_read,
        status_history=history_read,
        latest_summary=summary_read,
    )


@router.patch("/{incident_id}/status", response_model=IncidentRead)
def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
):
    """Transition incident status with analyst rationale and immutable audit trail."""
    updated = IncidentService.update_status(
        db,
        incident_id=incident_id,
        new_status=payload.status,
        notes=payload.notes,
        analyst=payload.analyst,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return IncidentRead(
        id=updated.id,
        title=updated.title,
        status=updated.status,
        priority=updated.priority,
        score=updated.score,
        created_at=updated.created_at,
        updated_at=updated.updated_at,
        first_seen=updated.first_seen,
        last_seen=updated.last_seen,
        primary_user=updated.primary_user,
        primary_host=updated.primary_host,
        correlated_indicators=updated.correlated_indicators or [],
        alert_count=updated.alert_count,
    )


@router.post("/{incident_id}/analyze", response_model=EvidenceSummaryRead)
def analyze_incident_evidence(
    incident_id: str,
    payload: AnalyzeRequest,
    db: Session = Depends(get_db),
):
    """Generate or refresh grounded evidence summary and timeline for the incident."""
    summary = IncidentService.generate_or_update_summary(db, incident_id, use_llm=payload.use_llm)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return EvidenceSummaryRead(
        id=summary.id,
        incident_id=summary.incident_id,
        summary_type=summary.summary_type,
        concise_summary=summary.concise_summary,
        observed_facts=summary.observed_facts or [],
        inferred_hypotheses=summary.inferred_hypotheses or [],
        chronological_timeline=summary.chronological_timeline or [],
        recommended_actions=summary.recommended_actions or [],
        is_validated=summary.is_validated,
        generated_at=summary.generated_at,
    )
