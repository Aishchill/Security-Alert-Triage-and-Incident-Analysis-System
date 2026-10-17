"""Tests verifying dashboard imports, queries, and synthetic scenario loading."""

import json
import os
from sqlalchemy import select, func
from app.correlation.engine import CorrelationEngine
from app.ingestion.json_ingest import parse_and_normalize_json
from app.models.alert import AlertModel
from app.models.incident import IncidentModel
from app.services.alert_service import AlertService
from app.services.incident_service import IncidentService


def test_synthetic_alerts_loading(db_session):
    """Test loading synthetic scenarios and asserting end-to-end incident generation."""
    data_path = os.path.join(os.path.dirname(__file__), "../data/synthetic_alerts.json")
    assert os.path.exists(data_path)

    with open(data_path, "r", encoding="utf-8") as f:
        synthetic_records = json.load(f)

    alerts, errors = parse_and_normalize_json(synthetic_records)
    assert len(errors) == 0
    assert len(alerts) == len(synthetic_records)

    saved_models, dup_count = AlertService.save_alerts_batch(db_session, alerts)
    assert len(saved_models) == len(synthetic_records)
    assert dup_count == 0

    created_incidents, updated_incidents = CorrelationEngine.correlate_batch(db_session, saved_models)
    assert len(created_incidents) > 0

    # Verify that multi-stage attack alerts on admin and dc01.corp were correlated
    admin_incidents = list(
        db_session.execute(
            select(IncidentModel).where(IncidentModel.primary_user == "admin")
        ).scalars().all()
    )
    assert len(admin_incidents) >= 1
    admin_inc = admin_incidents[0]
    assert admin_inc.priority == "CRITICAL"
    assert admin_inc.alert_count >= 3
    # Verify dc01 alerts are linked
    linked_hosts = [l.alert.host_entity for l in admin_inc.alert_links if l.alert]
    assert "dc01.corp.internal" in linked_hosts

    # Verify evidence summary generation
    summary = IncidentService.generate_or_update_summary(db_session, admin_inc.id, use_llm=False)
    assert summary is not None
    assert len(summary.observed_facts) >= 2
    assert len(summary.inferred_hypotheses) >= 1
    assert len(summary.chronological_timeline) >= 2
