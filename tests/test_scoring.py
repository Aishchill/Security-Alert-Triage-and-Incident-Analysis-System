"""Unit tests for the Deterministic Explainable Scoring Engine."""

from datetime import datetime, timezone
from app.config import AssetCriticalityLevel, IncidentPriority, SeverityLevel
from app.models.alert import AlertModel
from app.scoring.engine import ScoringEngine


def create_test_alert(
    severity="MEDIUM",
    confidence=0.5,
    asset_criticality="MEDIUM",
    event_type="TestAlert",
    user=None,
    indicators=None,
):
    """Helper to instantiate AlertModel with explicit parameters."""
    return AlertModel(
        id=f"test-{datetime.now(timezone.utc).timestamp()}",
        source_event_id="TEST-01",
        source="TestEDR",
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        severity=severity,
        confidence=confidence,
        user_entity=user,
        host_entity="host-01",
        asset_criticality=asset_criticality,
        indicators=indicators or [],
        title=f"Alert {event_type}",
        description="Testing scoring",
        raw_payload={},
        deduplication_hash="hash-1",
    )


def test_scoring_determinism():
    """Test that identical alerts produce identical scores and explanations."""
    alert1 = create_test_alert(severity="HIGH", confidence=0.8, asset_criticality="HIGH")
    res1 = ScoringEngine.evaluate_incident([alert1])
    res2 = ScoringEngine.evaluate_incident([alert1])

    assert res1.score == res2.score
    assert res1.priority == res2.priority
    assert len(res1.factors) == len(res2.factors)
    for f1, f2 in zip(res1.factors, res2.factors):
        assert f1.factor == f2.factor
        assert f1.points == f2.points


def test_scoring_factor_breakdown_transparency():
    """Test that every factor contributes transparent points in the breakdown."""
    alert = create_test_alert(
        severity="CRITICAL",
        confidence=1.0,
        asset_criticality="TIER_1_CRITICAL",
        event_type="RansomwareDetected",
        user="administrator",
        indicators=["c2.badactor.com", "sha256_hash_here"],
    )

    result = ScoringEngine.evaluate_incident([alert])
    assert result.priority == IncidentPriority.CRITICAL
    assert result.score >= 80.0

    factor_names = [f.factor for f in result.factors]
    assert "Base Severity" in factor_names
    assert "Telemetry Confidence" in factor_names
    assert "Asset Criticality" in factor_names
    assert "Privileged Account Exposure" in factor_names
    assert "Threat Indicators" in factor_names

    # Assert sum of factors matches score (subject to min 0, max 100 capping)
    calculated_sum = sum(f.points for f in result.factors)
    expected_score = min(100.0, round(calculated_sum, 1))
    assert result.score == expected_score


def test_multi_stage_chain_escalation():
    """Test that multiple distinct attack stages escalate the incident score."""
    a1 = create_test_alert(event_type="BruteForce", severity="MEDIUM")
    a2 = create_test_alert(event_type="PrivilegeEscalation", severity="MEDIUM")
    a3 = create_test_alert(event_type="C2Beaconing", severity="MEDIUM")

    single_stage_res = ScoringEngine.evaluate_incident([a1])
    multi_stage_res = ScoringEngine.evaluate_incident([a1, a2, a3])

    # Multi-stage incident must score higher due to attack chain bonus
    assert multi_stage_res.score > single_stage_res.score

    chain_factor = next(
        f for f in multi_stage_res.factors if f.factor == "Multi-Stage Attack Chain"
    )
    assert chain_factor.points == 10.0  # 2 extra stages * 5.0 pts
    assert chain_factor.value == 3


def test_conservative_missing_data_handling():
    """Test conservative default application when confidence or asset tier is missing."""
    alert = AlertModel(
        id="no-meta",
        source_event_id="META-01",
        source="Generic",
        timestamp=datetime.now(timezone.utc),
        event_type="Anomaly",
        severity="LOW",
        confidence=None,
        user_entity=None,
        host_entity=None,
        asset_criticality=None,
        indicators=[],
        title="Unknown",
        description="",
        raw_payload={},
        deduplication_hash="hash-x",
    )

    result = ScoringEngine.evaluate_incident([alert])
    assert result.score > 0
    assert len(result.conservative_defaults) >= 1

    default_factors = [n.factor for n in result.conservative_defaults]
    assert "Confidence" in default_factors or "Asset Criticality" in default_factors
