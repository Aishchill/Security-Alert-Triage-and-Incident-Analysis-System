"""Unit and integration tests for the Event Correlation Engine."""

from datetime import datetime, timedelta, timezone
from app.config import IncidentPriority
from app.correlation.engine import CorrelationEngine
from app.schemas.alert import CanonicalAlert
from app.services.alert_service import AlertService


def test_correlate_related_alerts_same_host(db_session):
    """Test that two alerts targeting the same host within the time window group into a single incident."""
    now = datetime.now(timezone.utc)
    raw1 = {
        "source_event_id": "EDR-101",
        "source": "CrowdStrike",
        "timestamp": now.isoformat(),
        "event_type": "BruteForce",
        "severity": "HIGH",
        "confidence": 0.8,
        "user": "jdoe",
        "host": "srv-db-01.corp",
        "asset_criticality": "HIGH",
        "indicators": ["192.168.1.50"],
    }
    raw2 = {
        "source_event_id": "EDR-102",
        "source": "CrowdStrike",
        "timestamp": (now + timedelta(minutes=15)).isoformat(),
        "event_type": "PrivilegeEscalation",
        "severity": "CRITICAL",
        "confidence": 0.9,
        "user": "admin",
        "host": "srv-db-01.corp",
        "asset_criticality": "HIGH",
        "indicators": ["mimikatz.exe"],
    }

    c1 = CanonicalAlert.from_raw(raw1)
    c2 = CanonicalAlert.from_raw(raw2)

    a1, _ = AlertService.save_alert(db_session, c1)
    a2, _ = AlertService.save_alert(db_session, c2)

    created_ids, updated_ids = CorrelationEngine.correlate_batch(db_session, [a1, a2])

    assert len(created_ids) == 1
    assert len(updated_ids) == 1
    assert created_ids[0] == updated_ids[0]

    # Inspect the correlated incident
    incident, is_new = CorrelationEngine.correlate_alert(db_session, a1)
    assert incident.alert_count == 2
    assert incident.primary_host == "srv-db-01.corp"
    assert "mimikatz.exe" in incident.correlated_indicators
    assert "192.168.1.50" in incident.correlated_indicators
    assert len(incident.alert_links) == 2
    reasons = [link.correlation_reason for link in incident.alert_links]
    assert "INITIAL_TRIGGER" in reasons
    assert any("HOST_MATCH" in r for r in reasons)


def test_prevent_unrelated_event_grouping(db_session):
    """Test that alerts with different hosts, users, IOCs form distinct incidents."""
    now = datetime.now(timezone.utc)
    raw1 = {
        "source_event_id": "A-1",
        "source": "EDR",
        "timestamp": now.isoformat(),
        "event_type": "Malware",
        "severity": "LOW",
        "user": "alice",
        "host": "workstation-alpha",
        "indicators": ["10.0.0.1"],
    }
    raw2 = {
        "source_event_id": "B-1",
        "source": "Firewall",
        "timestamp": (now + timedelta(minutes=5)).isoformat(),
        "event_type": "PortScan",
        "severity": "LOW",
        "user": "bob",
        "host": "workstation-beta",
        "indicators": ["172.16.0.99"],
    }

    a1, _ = AlertService.save_alert(db_session, CanonicalAlert.from_raw(raw1))
    a2, _ = AlertService.save_alert(db_session, CanonicalAlert.from_raw(raw2))

    inc1, is_new1 = CorrelationEngine.correlate_alert(db_session, a1)
    inc2, is_new2 = CorrelationEngine.correlate_alert(db_session, a2)

    assert is_new1 is True
    assert is_new2 is True
    assert inc1.id != inc2.id
    assert inc1.alert_count == 1
    assert inc2.alert_count == 1


def test_correlation_time_window_expiration(db_session):
    """Test that alerts sharing host outside the correlation window create a new incident."""
    now = datetime.now(timezone.utc)
    raw1 = {
        "source_event_id": "W-1",
        "source": "EDR",
        "timestamp": now.isoformat(),
        "event_type": "LoginFailed",
        "host": "finance-pc",
    }
    # 3 hours later (window is 60 minutes)
    raw2 = {
        "source_event_id": "W-2",
        "source": "EDR",
        "timestamp": (now + timedelta(hours=3)).isoformat(),
        "event_type": "LoginFailed",
        "host": "finance-pc",
    }

    a1, _ = AlertService.save_alert(db_session, CanonicalAlert.from_raw(raw1))
    a2, _ = AlertService.save_alert(db_session, CanonicalAlert.from_raw(raw2))

    inc1, _ = CorrelationEngine.correlate_alert(db_session, a1, window_minutes=60)
    inc2, _ = CorrelationEngine.correlate_alert(db_session, a2, window_minutes=60)

    assert inc1.id != inc2.id
