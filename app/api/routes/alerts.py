"""FastAPI router for alert ingestion and queries."""

from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session
from app.correlation.engine import CorrelationEngine
from app.database import get_db
from app.ingestion.csv_ingest import parse_and_normalize_csv
from app.ingestion.json_ingest import parse_and_normalize_json
from app.schemas.alert import (
    AlertDetailRead,
    AlertRead,
    IngestResult,
)
from app.schemas.incident import PaginatedResponse
from app.services.alert_service import AlertService

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.post("/ingest/json", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
def ingest_json_alerts(
    payload: Union[Dict[str, Any], List[Dict[str, Any]]],
    db: Session = Depends(get_db),
):
    """Ingest, validate, deduplicate, and correlate JSON alerts."""
    canonical_alerts, errors = parse_and_normalize_json(payload)

    total_received = len(payload) if isinstance(payload, list) else 1
    if not canonical_alerts and errors:
        return IngestResult(
            total_received=total_received,
            accepted_count=0,
            duplicate_count=0,
            rejected_count=len(errors),
            created_incidents=[],
            updated_incidents=[],
            errors=errors,
        )

    # Idempotent persistence
    saved_models, duplicate_count = AlertService.save_alerts_batch(db, canonical_alerts)

    # Correlate newly persisted alerts into incidents
    created_incidents, updated_incidents = CorrelationEngine.correlate_batch(db, saved_models)

    return IngestResult(
        total_received=total_received,
        accepted_count=len(saved_models),
        duplicate_count=duplicate_count,
        rejected_count=len(errors),
        created_incidents=created_incidents,
        updated_incidents=updated_incidents,
        errors=errors,
    )


@router.post("/ingest/csv", response_model=IngestResult, status_code=status.HTTP_201_CREATED)
async def ingest_csv_alerts(
    file: Optional[UploadFile] = File(None),
    raw_csv: Optional[str] = Query(None, description="Optional raw CSV string"),
    db: Session = Depends(get_db),
):
    """Ingest, validate, deduplicate, and correlate CSV alerts."""
    if file:
        content = await file.read()
    elif raw_csv:
        content = raw_csv.encode("utf-8")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either a CSV file upload or raw_csv parameter must be provided.",
        )

    canonical_alerts, errors = parse_and_normalize_csv(content)
    total_received = len(canonical_alerts) + len(errors)

    saved_models, duplicate_count = AlertService.save_alerts_batch(db, canonical_alerts)
    created_incidents, updated_incidents = CorrelationEngine.correlate_batch(db, saved_models)

    return IngestResult(
        total_received=total_received,
        accepted_count=len(saved_models),
        duplicate_count=duplicate_count,
        rejected_count=len(errors),
        created_incidents=created_incidents,
        updated_incidents=updated_incidents,
        errors=errors,
    )


@router.get("", response_model=PaginatedResponse[AlertRead])
def list_alerts(
    source: Optional[str] = None,
    severity: Optional[str] = None,
    user: Optional[str] = None,
    host: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieve paginated list of alerts with optional filters."""
    items, total = AlertService.list_alerts(
        db, source=source, severity=severity, user=user, host=host, limit=limit, offset=offset
    )
    
    # Map models to AlertRead
    results = []
    for item in items:
        inc_id = item.incident_links[0].incident_id if item.incident_links else None
        read_obj = AlertRead(
            id=item.id,
            source_event_id=item.source_event_id,
            source=item.source,
            timestamp=item.timestamp,
            ingested_at=item.ingested_at,
            event_type=item.event_type,
            severity=item.severity,
            confidence=item.confidence,
            user_entity=item.user_entity,
            host_entity=item.host_entity,
            asset_criticality=item.asset_criticality,
            source_ip=item.source_ip,
            destination_ip=item.destination_ip,
            destination_port=item.destination_port,
            indicators=item.indicators or [],
            title=item.title,
            description=item.description,
            deduplication_hash=item.deduplication_hash,
            incident_id=inc_id,
        )
        results.append(read_obj)

    return PaginatedResponse(items=results, total=total, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=AlertDetailRead)
def get_alert_detail(alert_id: str, db: Session = Depends(get_db)):
    """Retrieve full alert details including raw forensic payload."""
    alert = AlertService.get_by_id(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )
    inc_id = alert.incident_links[0].incident_id if alert.incident_links else None
    return AlertDetailRead(
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
        raw_payload=alert.raw_payload or {},
        incident_id=inc_id,
    )
