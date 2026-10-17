"""Pydantic schemas for Incident representations and operations."""

from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field
from app.config import IncidentPriority, IncidentStatus
from app.schemas.alert import AlertRead
from app.schemas.scoring import ScoreFactorBreakdown

T = TypeVar("T")


class IncidentStatusUpdate(BaseModel):
    """Payload for updating incident triage status."""
    status: IncidentStatus
    notes: str = Field(default="", description="Analyst rationale for status change")
    analyst: str = Field(default="soc_analyst", description="Analyst identity")


class IncidentAlertLinkRead(BaseModel):
    """Link between an incident and an alert."""
    id: str
    incident_id: str
    alert_id: str
    correlation_reason: str
    linked_at: datetime
    alert: Optional[AlertRead] = None

    model_config = {"from_attributes": True}


class IncidentStatusHistoryRead(BaseModel):
    """Audit log entry for incident status change."""
    id: str
    incident_id: str
    old_status: str
    new_status: str
    notes: str
    changed_by: str
    timestamp: datetime

    model_config = {"from_attributes": True}


class IncidentRead(BaseModel):
    """Incident listing representation."""
    id: str
    title: str
    status: IncidentStatus
    priority: IncidentPriority
    score: float
    created_at: datetime
    updated_at: datetime
    first_seen: datetime
    last_seen: datetime
    primary_user: Optional[str] = None
    primary_host: Optional[str] = None
    correlated_indicators: List[str] = Field(default_factory=list)
    alert_count: int

    model_config = {"from_attributes": True}


class EvidenceSummaryRead(BaseModel):
    """Schema for returning grounded incident evidence summary."""
    id: str
    incident_id: str
    summary_type: str
    concise_summary: str
    observed_facts: List[str]
    inferred_hypotheses: List[str]
    chronological_timeline: List[Dict[str, Any]]
    recommended_actions: List[str]
    is_validated: bool
    generated_at: datetime

    model_config = {"from_attributes": True}


class IncidentDetailRead(IncidentRead):
    """Detailed incident view with linked alerts, scoring explanation, and analysis."""
    score_breakdown: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[AlertRead] = Field(default_factory=list)
    alert_links: List[IncidentAlertLinkRead] = Field(default_factory=list)
    status_history: List[IncidentStatusHistoryRead] = Field(default_factory=list)
    latest_summary: Optional[EvidenceSummaryRead] = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard pagination envelope."""
    items: List[T]
    total: int
    limit: int
    offset: int
