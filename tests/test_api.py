"""Integration tests for the FastAPI REST API."""

import pytest
from fastapi.testclient import TestClient
from app.api.app import app
from app.database import Base, get_db


@pytest.fixture
def client(db_session):
    """Provide a TestClient using the test database session."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_health_endpoint(client):
    """Test health check route."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["database_connected"] is True


def test_ingest_json_and_query_alerts(client, sample_json_alert):
    """Test full JSON ingestion lifecycle and querying."""
    # 1. Ingest alert
    ingest_res = client.post("/api/v1/alerts/ingest/json", json=sample_json_alert)
    assert ingest_res.status_code == 201
    ingest_data = ingest_res.json()
    assert ingest_data["accepted_count"] == 1
    assert ingest_data["duplicate_count"] == 0
    assert len(ingest_data["created_incidents"]) == 1

    inc_id = ingest_data["created_incidents"][0]

    # 2. Ingest identical alert again -> must deduplicate
    dup_res = client.post("/api/v1/alerts/ingest/json", json=sample_json_alert)
    assert dup_res.status_code == 201
    dup_data = dup_res.json()
    assert dup_data["accepted_count"] == 0
    assert dup_data["duplicate_count"] == 1

    # 3. Query alerts
    list_res = client.get("/api/v1/alerts")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] == 1
    alert_id = list_data["items"][0]["id"]
    assert list_data["items"][0]["source_event_id"] == "EDR-99120"
    assert list_data["items"][0]["incident_id"] == inc_id

    # 4. Query alert detail with forensic raw_payload
    detail_res = client.get(f"/api/v1/alerts/{alert_id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert "raw_payload" in detail_data
    assert detail_data["raw_payload"]["source_event_id"] == "EDR-99120"


def test_ingest_csv_endpoint(client):
    """Test CSV ingestion via raw_csv parameter."""
    csv_body = """source_event_id,source,event_type,severity,confidence,host,user
CSV-API-1,CrowdStrike,BruteForce,HIGH,0.85,finance-dc,admin
CSV-API-2,CrowdStrike,PrivEsc,CRITICAL,0.95,finance-dc,admin
"""
    res = client.post("/api/v1/alerts/ingest/csv", params={"raw_csv": csv_body})
    assert res.status_code == 201
    data = res.json()
    assert data["accepted_count"] == 2
    assert data["rejected_count"] == 0
    # Both alerts on same host/user must merge into 1 incident
    assert len(data["created_incidents"]) == 1
    assert len(data["updated_incidents"]) == 1


def test_incident_lifecycle_and_status_update(client, sample_json_alert):
    """Test incident retrieval, explainability breakdown, and status triage update."""
    # Ingest alert to trigger incident
    client.post("/api/v1/alerts/ingest/json", json=sample_json_alert)

    # 1. Query incidents
    inc_list_res = client.get("/api/v1/incidents")
    assert inc_list_res.status_code == 200
    inc_data = inc_list_res.json()
    assert inc_data["total"] >= 1
    incident_id = inc_data["items"][0]["id"]

    # 2. Get incident details
    detail_res = client.get(f"/api/v1/incidents/{incident_id}")
    assert detail_res.status_code == 200
    incident_detail = detail_res.json()
    assert incident_detail["id"] == incident_id
    assert len(incident_detail["score_breakdown"]) > 0
    assert len(incident_detail["alerts"]) == 1
    assert incident_detail["latest_summary"] is not None
    assert len(incident_detail["latest_summary"]["observed_facts"]) >= 1

    # 3. Transition status to INVESTIGATING with notes
    status_payload = {
        "status": "INVESTIGATING",
        "notes": "Analyst verified PowerShell script execution; initiating host isolation.",
        "analyst": "alice_secops",
    }
    update_res = client.patch(f"/api/v1/incidents/{incident_id}/status", json=status_payload)
    assert update_res.status_code == 200
    assert update_res.json()["status"] == "INVESTIGATING"

    # Verify audit history
    detail_after = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert len(detail_after["status_history"]) >= 2
    assert detail_after["status_history"][-1]["new_status"] == "INVESTIGATING"
    assert "initiating host isolation" in detail_after["status_history"][-1]["notes"]


def test_incident_reanalysis_endpoint(client, sample_json_alert):
    """Test triggering re-analysis / evidence summary generation on an incident."""
    client.post("/api/v1/alerts/ingest/json", json=sample_json_alert)
    inc_id = client.get("/api/v1/incidents").json()["items"][0]["id"]

    analyze_res = client.post(f"/api/v1/incidents/{inc_id}/analyze", json={"use_llm": False})
    assert analyze_res.status_code == 200
    summary = analyze_res.json()
    assert summary["summary_type"] == "DETERMINISTIC"
    assert len(summary["observed_facts"]) >= 1
    assert len(summary["recommended_actions"]) >= 1
