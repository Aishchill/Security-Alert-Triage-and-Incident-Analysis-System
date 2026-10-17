"""Pydantic schemas for Alert ingestion, normalization, and representation."""

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4
from pydantic import BaseModel, Field, field_validator, model_validator
from app.config import AssetCriticalityLevel, SeverityLevel


class RawAlertInput(BaseModel):
    """Flexible incoming alert payload supporting disparate naming conventions."""
    
    # Tolerates various key names for maximum source interoperability
    source_event_id: Optional[Union[str, int]] = None
    event_id: Optional[Union[str, int]] = None
    id: Optional[Union[str, int]] = None

    source: Optional[str] = None
    tool: Optional[str] = None
    vendor: Optional[str] = None

    timestamp: Optional[Union[datetime, str, int, float]] = None
    time: Optional[Union[datetime, str, int, float]] = None
    created_at: Optional[Union[datetime, str, int, float]] = None

    event_type: Optional[str] = None
    type: Optional[str] = None
    action: Optional[str] = None

    severity: Optional[Union[str, int]] = None
    confidence: Optional[Union[float, int, str]] = None

    user: Optional[str] = None
    username: Optional[str] = None
    user_entity: Optional[str] = None

    host: Optional[str] = None
    hostname: Optional[str] = None
    asset: Optional[str] = None
    host_entity: Optional[str] = None

    asset_criticality: Optional[str] = None

    source_ip: Optional[str] = None
    src_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    destination_port: Optional[Union[int, str]] = None
    dest_port: Optional[Union[int, str]] = None
    dst_port: Optional[Union[int, str]] = None

    indicators: Optional[Union[List[str], Dict[str, Any], str]] = None
    title: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    message: Optional[str] = None
    details: Optional[str] = None

    # Allows arbitrary extra fields
    model_config = {"extra": "allow"}


class CanonicalAlert(BaseModel):
    """Validated, normalized security alert record."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source_event_id: str
    source: str
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    user_entity: Optional[str] = None
    host_entity: Optional[str] = None
    asset_criticality: AssetCriticalityLevel = AssetCriticalityLevel.MEDIUM
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    indicators: List[str] = Field(default_factory=list)
    title: str
    description: str = ""
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    deduplication_hash: str = ""

    @classmethod
    def from_raw(cls, raw: Union[RawAlertInput, Dict[str, Any]]) -> "CanonicalAlert":
        """Normalize disparate raw input into a strictly validated CanonicalAlert."""
        if isinstance(raw, RawAlertInput):
            data = raw.model_dump(exclude_unset=False)
        else:
            data = dict(raw)

        # 1. Resolve source_event_id
        source_event_id = str(
            data.get("source_event_id") or data.get("event_id") or data.get("id") or ""
        ).strip()

        # 2. Resolve source
        source = str(data.get("source") or data.get("tool") or data.get("vendor") or "Generic_SIEM").strip()

        # 3. Resolve event_type
        event_type = str(data.get("event_type") or data.get("type") or data.get("action") or "SecurityAlert").strip()

        # 4. Resolve timestamp
        ts_raw = data.get("timestamp") or data.get("time") or data.get("created_at")
        ts = cls._normalize_timestamp(ts_raw)

        # 5. Resolve severity
        sev_raw = data.get("severity")
        severity = cls._normalize_severity(sev_raw)

        # 6. Resolve confidence (0.0 - 1.0)
        conf_raw = data.get("confidence")
        confidence = cls._normalize_confidence(conf_raw)

        # 7. Resolve user entity
        user = data.get("user") or data.get("username") or data.get("user_entity")
        user_entity = str(user).strip().lower() if user else None

        # 8. Resolve host entity
        host = data.get("host") or data.get("hostname") or data.get("asset") or data.get("host_entity")
        host_entity = str(host).strip().lower() if host else None

        # 9. Resolve asset criticality
        crit_raw = data.get("asset_criticality")
        asset_crit = cls._normalize_asset_criticality(crit_raw)

        # 10. Resolve network endpoints
        source_ip = data.get("source_ip") or data.get("src_ip")
        destination_ip = data.get("destination_ip") or data.get("dest_ip") or data.get("dst_ip")
        
        dst_port_raw = data.get("destination_port") or data.get("dest_port") or data.get("dst_port")
        destination_port: Optional[int] = None
        if dst_port_raw is not None and str(dst_port_raw).strip() != "":
            try:
                destination_port = int(dst_port_raw)
            except (ValueError, TypeError):
                destination_port = None

        # 11. Resolve indicators
        indicators = cls._normalize_indicators(data.get("indicators"))

        # 12. Resolve title and description
        title = str(data.get("title") or data.get("name") or f"{event_type} on {host_entity or user_entity or 'Unknown'}").strip()
        description = str(data.get("description") or data.get("message") or data.get("details") or "").strip()

        # 13. Deduplication hash calculation
        if source_event_id:
            raw_hash_input = f"{source.lower()}::{source_event_id}"
        else:
            # Fallback fingerprint if external tool omitted event ID
            raw_hash_input = f"{source.lower()}::{ts.isoformat()}::{event_type.lower()}::{host_entity or ''}::{user_entity or ''}::{title.lower()}"
            source_event_id = f"gen-{hashlib.md5(raw_hash_input.encode('utf-8')).hexdigest()[:12]}"

        dedup_hash = hashlib.sha256(raw_hash_input.encode("utf-8")).hexdigest()

        return cls(
            source_event_id=source_event_id,
            source=source,
            timestamp=ts,
            event_type=event_type,
            severity=severity,
            confidence=confidence,
            user_entity=user_entity,
            host_entity=host_entity,
            asset_criticality=asset_crit,
            source_ip=str(source_ip).strip() if source_ip else None,
            destination_ip=str(destination_ip).strip() if destination_ip else None,
            destination_port=destination_port,
            indicators=indicators,
            title=title,
            description=description,
            raw_payload=data,
            deduplication_hash=dedup_hash,
        )

    @staticmethod
    def _normalize_timestamp(val: Any) -> datetime:
        """Parse varied timestamp representations into timezone-aware UTC datetime."""
        if val is None or str(val).strip() == "":
            return datetime.now(timezone.utc)
        
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val.astimezone(timezone.utc)

        if isinstance(val, (int, float)):
            # Distinguish seconds vs milliseconds
            if val > 1e11:  # Milliseconds
                val = val / 1000.0
            return datetime.fromtimestamp(val, tz=timezone.utc)

        val_str = str(val).strip()
        # Common ISO format with or without 'Z'
        try:
            cleaned = val_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

        # Try Unix timestamp string
        try:
            num = float(val_str)
            if num > 1e11:
                num = num / 1000.0
            return datetime.fromtimestamp(num, tz=timezone.utc)
        except ValueError:
            pass

        # Fallback to current time if completely unparseable
        return datetime.now(timezone.utc)

    @staticmethod
    def _normalize_severity(val: Any) -> SeverityLevel:
        """Conservative mapping of severity representations."""
        if val is None:
            return SeverityLevel.MEDIUM

        v = str(val).strip().upper()
        if v in ("CRITICAL", "CRIT", "5", "FATAL"):
            return SeverityLevel.CRITICAL
        if v in ("HIGH", "4", "ERR", "ERROR"):
            return SeverityLevel.HIGH
        if v in ("MEDIUM", "MED", "3", "WARN", "WARNING"):
            return SeverityLevel.MEDIUM
        if v in ("LOW", "2"):
            return SeverityLevel.LOW
        if v in ("INFORMATIONAL", "INFO", "1", "DEBUG"):
            return SeverityLevel.INFORMATIONAL

        return SeverityLevel.MEDIUM

    @staticmethod
    def _normalize_confidence(val: Any) -> float:
        """Normalize confidence to [0.0, 1.0]. Conservative default: 0.5."""
        if val is None or str(val).strip() == "":
            return 0.5
        try:
            c = float(val)
            if c > 1.0 and c <= 100.0:
                c = c / 100.0
            return max(0.0, min(1.0, round(c, 3)))
        except (ValueError, TypeError):
            return 0.5

    @staticmethod
    def _normalize_asset_criticality(val: Any) -> AssetCriticalityLevel:
        """Normalize asset criticality. Conservative default: MEDIUM."""
        if val is None:
            return AssetCriticalityLevel.MEDIUM
        v = str(val).strip().upper().replace(" ", "_").replace("-", "_")
        if "TIER_1" in v or "CRITICAL" in v or "TIER1" in v:
            return AssetCriticalityLevel.TIER_1_CRITICAL
        if "HIGH" in v:
            return AssetCriticalityLevel.HIGH
        if "LOW" in v:
            return AssetCriticalityLevel.LOW
        return AssetCriticalityLevel.MEDIUM

    @staticmethod
    def _normalize_indicators(val: Any) -> List[str]:
        """Normalize indicators list, extracting unique non-empty tokens."""
        if not val:
            return []
        result: List[str] = []
        if isinstance(val, str):
            # Might be comma or semicolon separated
            if val.strip().startswith("[") and val.strip().endswith("]"):
                try:
                    parsed = json.loads(val)
                    return CanonicalAlert._normalize_indicators(parsed)
                except Exception:
                    pass
            tokens = [t.strip() for t in re.split(r"[,;\s]+", val) if t.strip()]
            result.extend(tokens)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, (str, int, float)):
                    s = str(item).strip()
                    if s:
                        result.append(s)
                elif isinstance(item, dict):
                    for v in item.values():
                        s = str(v).strip()
                        if s:
                            result.append(s)
        elif isinstance(val, dict):
            for v in val.values():
                if isinstance(v, list):
                    result.extend(CanonicalAlert._normalize_indicators(v))
                elif isinstance(v, (str, int, float)):
                    s = str(v).strip()
                    if s:
                        result.append(s)
        
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for item in result:
            if item.lower() not in seen:
                seen.add(item.lower())
                unique.append(item)
        return unique


class AlertRead(BaseModel):
    """Schema for returning alert details via API and UI."""

    id: str
    source_event_id: str
    source: str
    timestamp: datetime
    ingested_at: datetime
    event_type: str
    severity: str
    confidence: float
    user_entity: Optional[str] = None
    host_entity: Optional[str] = None
    asset_criticality: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    indicators: List[str] = Field(default_factory=list)
    title: str
    description: str
    deduplication_hash: str
    incident_id: Optional[str] = None

    model_config = {"from_attributes": True}


class AlertDetailRead(AlertRead):
    """Detailed alert schema including untouched forensic raw_payload."""
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class IngestionErrorDetail(BaseModel):
    """Row or item level validation error report."""
    item_index: int
    raw_data: Optional[Dict[str, Any]] = None
    errors: List[str]


class IngestResult(BaseModel):
    """Summary of batch ingestion operation."""
    total_received: int
    accepted_count: int
    duplicate_count: int
    rejected_count: int
    created_incidents: List[str] = Field(default_factory=list)
    updated_incidents: List[str] = Field(default_factory=list)
    errors: List[IngestionErrorDetail] = Field(default_factory=list)
