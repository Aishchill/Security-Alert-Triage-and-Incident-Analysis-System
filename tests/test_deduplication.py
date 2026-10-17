"""Tests for alert persistence, deduplication, and database idempotency."""

from app.schemas.alert import CanonicalAlert
from app.services.alert_service import AlertService


def test_save_alert_and_deduplicate(db_session, sample_json_alert):
    """Test saving a new alert and asserting deduplication on second attempt."""
    canonical = CanonicalAlert.from_raw(sample_json_alert)

    # 1. First save: must succeed as a new alert
    model, is_duplicate = AlertService.save_alert(db_session, canonical)
    assert not is_duplicate
    assert model.id == canonical.id
    assert model.source_event_id == "EDR-99120"
    assert model.deduplication_hash == canonical.deduplication_hash

    # 2. Second save with identical event data: must detect duplicate
    model2, is_duplicate2 = AlertService.save_alert(db_session, canonical)
    assert is_duplicate2
    assert model2.id == model.id  # Returns the existing record


def test_batch_deduplication(db_session, sample_json_alert):
    """Test batch save with repeated records inside and across batches."""
    alert1 = CanonicalAlert.from_raw(sample_json_alert)
    
    alert2_raw = dict(sample_json_alert)
    alert2_raw["source_event_id"] = "EDR-99121"
    alert2 = CanonicalAlert.from_raw(alert2_raw)

    batch = [alert1, alert2, alert1]  # alert1 repeated
    saved, dup_count = AlertService.save_alerts_batch(db_session, batch)

    assert len(saved) == 2
    assert dup_count == 1

    # Ingesting the same batch again should produce 0 new alerts and 3 duplicates
    saved_again, dup_count2 = AlertService.save_alerts_batch(db_session, batch)
    assert len(saved_again) == 0
    assert dup_count2 == 3


def test_list_alerts_with_filters(db_session, sample_json_alert):
    """Test querying and filtering persisted alerts."""
    for i in range(5):
        raw = dict(sample_json_alert)
        raw["source_event_id"] = f"EVT-{i}"
        raw["user"] = f"user_{i}"
        raw["severity"] = "HIGH" if i % 2 == 0 else "LOW"
        canonical = CanonicalAlert.from_raw(raw)
        AlertService.save_alert(db_session, canonical)

    # Filter by severity
    high_alerts, total_high = AlertService.list_alerts(db_session, severity="HIGH")
    assert total_high == 3
    assert len(high_alerts) == 3

    # Filter by user
    user_alerts, total_user = AlertService.list_alerts(db_session, user="user_0")
    assert total_user == 1
    assert user_alerts[0].user_entity == "user_0"
