"""Application configuration module."""

from dataclasses import dataclass, field
from enum import Enum
import os
from typing import Dict, List


class SeverityLevel(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AssetCriticalityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    TIER_1_CRITICAL = "TIER_1_CRITICAL"


class IncidentPriority(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class Settings:
    """System settings with configurable weights and thresholds."""

    APP_NAME: str = "Security Alert Triage and Incident Analysis System"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./security_triage.db")
    CORRELATION_WINDOW_MINUTES: int = int(os.getenv("CORRELATION_WINDOW_MINUTES", "60"))
    MAX_BATCH_SIZE: int = int(os.getenv("MAX_BATCH_SIZE", "1000"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Explainable Scoring Engine Weights (Configurable)
    SEVERITY_POINTS: Dict[str, float] = field(default_factory=lambda: {
        SeverityLevel.INFORMATIONAL.value: 5.0,
        SeverityLevel.LOW.value: 12.0,
        SeverityLevel.MEDIUM.value: 22.0,
        SeverityLevel.HIGH.value: 34.0,
        SeverityLevel.CRITICAL.value: 45.0,
    })

    ASSET_CRITICALITY_POINTS: Dict[str, float] = field(default_factory=lambda: {
        AssetCriticalityLevel.LOW.value: 5.0,
        AssetCriticalityLevel.MEDIUM.value: 10.0,
        AssetCriticalityLevel.HIGH.value: 18.0,
        AssetCriticalityLevel.TIER_1_CRITICAL.value: 25.0,
    })

    CONFIDENCE_WEIGHT: float = 15.0  # Multiplied by confidence (0.0 - 1.0)
    MULTI_STAGE_BONUS_PER_STAGE: float = 5.0  # Points per distinct attack type (up to max 15)
    MAX_MULTI_STAGE_BONUS: float = 15.0
    SENSITIVE_ACCOUNT_BONUS: float = 10.0
    INDICATOR_THREAT_BONUS: float = 10.0

    # Priority Classification Thresholds (Score out of 100)
    CRITICAL_THRESHOLD: float = 80.0
    HIGH_THRESHOLD: float = 60.0
    MEDIUM_THRESHOLD: float = 40.0
    LOW_THRESHOLD: float = 20.0

    # Sensitive Account Identifiers for Privilege Escalation Escalation
    SENSITIVE_USERS: List[str] = field(default_factory=lambda: [
        "admin", "administrator", "root", "system", "domain_admin",
        "corp\\administrator", "nt authority\\system", "service_account"
    ])


settings = Settings()
