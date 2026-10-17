"""Pydantic schemas for Explainable Prioritization and Scoring."""

from typing import Any, List
from pydantic import BaseModel, Field
from app.config import IncidentPriority


class ScoreFactorBreakdown(BaseModel):
    """Transparent mathematical component contributing to the final score."""
    factor: str
    points: float
    value: Any
    reason: str


class ConservativeDefaultNote(BaseModel):
    """Audit note explaining conservative handling of missing or incomplete data."""
    factor: str
    handling: str


class PrioritizationResult(BaseModel):
    """Full explainable incident scoring result."""
    score: float = Field(ge=0.0, le=100.0)
    priority: IncidentPriority
    factors: List[ScoreFactorBreakdown] = Field(default_factory=list)
    conservative_defaults: List[ConservativeDefaultNote] = Field(default_factory=list)
