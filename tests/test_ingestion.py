"""Unit tests for alert ingestion, normalization, and error isolation."""

import pytest
from app.config import AssetCriticalityLevel, SeverityLevel
from app.ingestion.csv_ingest import parse_and_normalize_csv
from app.ingestion.json_ingest import parse_and_normalize_json
from app.ingestion.normalizer import normalize_record
from app.schemas.alert import CanonicalAlert


def test_normalize_valid_alert(sample_json_alert):
    """Test normalizing a fully populated alert record."""
    alert, error = normalize_record(sample_json_alert)
    assert error is None
    assert alert is not None
    assert alert.source_event_id == "EDR-99120"
    assert alert.source == "CrowdStrike"
    assert alert.severity == SeverityLevel.HIGH
    assert alert.confidence == 0.85
    assert alert.user_entity == "jdoe"
    assert alert.host_entity == "wkstn-042.corp"
    assert alert.asset_criticality == AssetCriticalityLevel.MEDIUM
    assert alert.destination_port == 443
    assert len(alert.indicators) == 3
    assert alert.deduplication_hash != ""
    assert "powershell.exe" in alert.raw_payload["indicators"][0]


def test_normalize_missing_optional_fields():
    """Test conservative defaults for missing optional fields."""
    minimal_alert = {
        "event_id": "MIN-123",
        "tool": "CustomDetector",
    }
    alert, error = normalize_record(minimal_alert)
    assert error is None
    assert alert is not None
    assert alert.source_event_id == "MIN-123"
    assert alert.source == "CustomDetector"
    assert alert.severity == SeverityLevel.MEDIUM  # Default
    assert alert.confidence == 0.5  # Conservative default
    assert alert.asset_criticality == AssetCriticalityLevel.MEDIUM  # Conservative default
    assert alert.user_entity is None
    assert alert.host_entity is None
    assert alert.indicators == []


def test_normalize_invalid_and_empty_records():
    """Test rejection of non-dict or empty records."""
    # Empty dict
    alert, error = normalize_record({}, index=1)
    assert alert is None
    assert error is not None
    assert error.item_index == 1

    # Non-dict
    alert, error = normalize_record("string not a dict", index=2)  # type: ignore
    assert alert is None
    assert error is not None
    assert "JSON object" in error.errors[0]


def test_json_batch_parsing(sample_json_alert):
    """Test parsing a JSON list containing valid and invalid entries."""
    batch = [
        sample_json_alert,
        {},  # empty, should produce error detail
        {
            "id": "ALERT-002",
            "source": "AWS_GuardDuty",
            "type": "UnauthorizedAccess",
            "severity": "CRITICAL",
            "confidence": 99,  # Should normalize to 0.99
            "user": "root",
        },
    ]

    alerts, errors = parse_and_normalize_json(batch)
    assert len(alerts) == 2
    assert len(errors) == 1
    assert errors[0].item_index == 1
    assert alerts[1].confidence == 0.99
    assert alerts[1].severity == SeverityLevel.CRITICAL


def test_csv_parsing(sample_csv_data):
    """Test parsing CSV text into canonical alerts."""
    alerts, errors = parse_and_normalize_csv(sample_csv_data)
    assert len(errors) == 0
    assert len(alerts) == 3
    assert alerts[0].source_event_id == "CSV-001"
    assert alerts[0].event_type == "PortScan"
    assert alerts[1].user_entity == "admin"
    assert alerts[1].asset_criticality == AssetCriticalityLevel.TIER_1_CRITICAL
    assert alerts[2].confidence == 0.95
    assert alerts[2].severity == SeverityLevel.CRITICAL


def test_csv_malformed_rows():
    """Test CSV error isolation when lines are malformed or empty."""
    csv_text = """source_event_id,source,event_type,severity
VAL-1,EDR,BruteForce,HIGH
   
,,,
VAL-2,Suricata,C2,CRITICAL
"""
    alerts, errors = parse_and_normalize_csv(csv_text)
    # The completely empty commas row should be isolated as error
    assert len(alerts) == 2
    assert alerts[0].source_event_id == "VAL-1"
    assert alerts[1].source_event_id == "VAL-2"
