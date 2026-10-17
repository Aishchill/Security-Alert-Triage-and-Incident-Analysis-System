"""Pydantic schemas for Incident Analysis, Timeline, and Evidence Grounding."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TimelineEvent(BaseModel):
    """Chronological event representation grounded in a specific alert."""
    timestamp: datetime
    alert_id: str
    source_event_id: str
    event_type: str
    source: str
    summary: str
    entities: Dict[str, Any] = Field(default_factory=dict)


class StructuredIncidentAnalysis(BaseModel):
    """Factual, grounded incident summary strictly separating facts and hypotheses."""

    concise_summary: str = Field(
        description="Concise overview of what occurred, strictly grounded in evidence."
    )
    supporting_alert_ids: List[str] = Field(
        description="IDs of alerts supporting the summary."
    )
    observed_facts: List[str] = Field(
        description="Empirical, verifiable observations directly extracted from telemetry. Must cite alert IDs."
    )
    inferred_hypotheses: List[str] = Field(
        description="Analytic inferences and potential attack objectives, clearly segregated from facts."
    )
    chronological_timeline: List[TimelineEvent] = Field(
        description="Chronologically ordered sequence of observed events."
    )
    recommended_actions: List[str] = Field(
        description="Immediate containment, remediation, and verification steps."
    )
    is_validated: bool = Field(
        default=True,
        description="Whether the output has passed strict anti-hallucination validation."
    )
    validation_warnings: List[str] = Field(
        default_factory=list,
        description="Any warnings regarding ungrounded or pruned tokens."
    )
