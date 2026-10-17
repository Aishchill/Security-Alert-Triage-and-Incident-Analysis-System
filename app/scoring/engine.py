"""Deterministic, explainable scoring engine for incident prioritization."""

from typing import Any, Dict, List, Optional, Set
from app.config import (
    AssetCriticalityLevel,
    IncidentPriority,
    SeverityLevel,
    settings,
)
from app.models.alert import AlertModel
from app.schemas.scoring import (
    ConservativeDefaultNote,
    PrioritizationResult,
    ScoreFactorBreakdown,
)


class ScoringEngine:
    """100% deterministic Python scoring engine independent of LLMs."""

    # Severity ordering for picking maximum
    SEVERITY_ORDER = {
        SeverityLevel.INFORMATIONAL.value: 1,
        SeverityLevel.LOW.value: 2,
        SeverityLevel.MEDIUM.value: 3,
        SeverityLevel.HIGH.value: 4,
        SeverityLevel.CRITICAL.value: 5,
    }

    ASSET_CRITICALITY_ORDER = {
        AssetCriticalityLevel.LOW.value: 1,
        AssetCriticalityLevel.MEDIUM.value: 2,
        AssetCriticalityLevel.HIGH.value: 3,
        AssetCriticalityLevel.TIER_1_CRITICAL.value: 4,
    }

    @classmethod
    def evaluate_incident(cls, alerts: List[AlertModel]) -> PrioritizationResult:
        """Calculate score, priority level, and detailed factor-by-factor breakdown."""
        if not alerts:
            return PrioritizationResult(
                score=0.0,
                priority=IncidentPriority.INFORMATIONAL,
                factors=[
                    ScoreFactorBreakdown(
                        factor="Zero Alerts",
                        points=0.0,
                        value=0,
                        reason="Incident contains no associated alerts.",
                    )
                ],
                conservative_defaults=[],
            )

        factors: List[ScoreFactorBreakdown] = []
        conservative_notes: List[ConservativeDefaultNote] = []

        # 1. Base Severity Factor (Highest severity among all alerts)
        highest_sev = max(
            alerts,
            key=lambda a: cls.SEVERITY_ORDER.get(a.severity.upper(), 3),
        ).severity.upper()
        
        sev_points = settings.SEVERITY_POINTS.get(highest_sev, 22.0)
        factors.append(
            ScoreFactorBreakdown(
                factor="Base Severity",
                points=sev_points,
                value=highest_sev,
                reason=f"Maximum alert severity in incident is {highest_sev} (+{sev_points:.1f} pts).",
            )
        )

        # 2. Source Confidence Factor (Mean confidence of alerts)
        confidences = [a.confidence for a in alerts if a.confidence is not None]
        if confidences:
            avg_conf = sum(confidences) / len(confidences)
            conf_points = round(avg_conf * settings.CONFIDENCE_WEIGHT, 1)
            factors.append(
                ScoreFactorBreakdown(
                    factor="Telemetry Confidence",
                    points=conf_points,
                    value=round(avg_conf, 2),
                    reason=f"Average telemetry confidence across {len(alerts)} alert(s) is {avg_conf:.2f} (+{conf_points:.1f} pts).",
                )
            )
        else:
            avg_conf = 0.5
            conf_points = round(avg_conf * settings.CONFIDENCE_WEIGHT, 1)
            factors.append(
                ScoreFactorBreakdown(
                    factor="Telemetry Confidence",
                    points=conf_points,
                    value=0.5,
                    reason=f"Conservative default confidence 0.5 applied (+{conf_points:.1f} pts).",
                )
            )
            conservative_notes.append(
                ConservativeDefaultNote(
                    factor="Confidence",
                    handling="Missing confidence in telemetry; default 0.5 applied.",
                )
            )

        # 3. Asset Criticality Factor (Highest among affected assets)
        assets = [a for a in alerts if a.asset_criticality]
        if assets:
            highest_asset_alert = max(
                assets,
                key=lambda a: cls.ASSET_CRITICALITY_ORDER.get(a.asset_criticality.upper(), 2),
            )
            highest_crit = highest_asset_alert.asset_criticality.upper()
            host_name = highest_asset_alert.host_entity or "Host"
            crit_points = settings.ASSET_CRITICALITY_POINTS.get(highest_crit, 10.0)
            factors.append(
                ScoreFactorBreakdown(
                    factor="Asset Criticality",
                    points=crit_points,
                    value=highest_crit,
                    reason=f"Target asset '{host_name}' criticality tier is {highest_crit} (+{crit_points:.1f} pts).",
                )
            )
        else:
            crit_points = settings.ASSET_CRITICALITY_POINTS.get("MEDIUM", 10.0)
            factors.append(
                ScoreFactorBreakdown(
                    factor="Asset Criticality",
                    points=crit_points,
                    value="MEDIUM",
                    reason=f"Conservative default asset criticality MEDIUM applied (+{crit_points:.1f} pts).",
                )
            )
            conservative_notes.append(
                ConservativeDefaultNote(
                    factor="Asset Criticality",
                    handling="No asset tier specified; conservative MEDIUM default applied.",
                )
            )

        # 4. Multi-Stage Attack Chain Progression
        distinct_event_types: Set[str] = {a.event_type for a in alerts if a.event_type}
        if len(distinct_event_types) > 1:
            stage_bonus = min(
                (len(distinct_event_types) - 1) * settings.MULTI_STAGE_BONUS_PER_STAGE,
                settings.MAX_MULTI_STAGE_BONUS,
            )
            stage_names = ", ".join(sorted(distinct_event_types))
            factors.append(
                ScoreFactorBreakdown(
                    factor="Multi-Stage Attack Chain",
                    points=stage_bonus,
                    value=len(distinct_event_types),
                    reason=f"Detected {len(distinct_event_types)} distinct event types ({stage_names}) (+{stage_bonus:.1f} pts).",
                )
            )

        # 5. Privileged Account Exposure
        targeted_users = {a.user_entity.lower() for a in alerts if a.user_entity}
        sensitive_match = targeted_users.intersection(set(settings.SENSITIVE_USERS))
        if sensitive_match:
            matched_user = list(sensitive_match)[0]
            factors.append(
                ScoreFactorBreakdown(
                    factor="Privileged Account Exposure",
                    points=settings.SENSITIVE_ACCOUNT_BONUS,
                    value=matched_user,
                    reason=f"Privileged user account '{matched_user}' targeted (+{settings.SENSITIVE_ACCOUNT_BONUS:.1f} pts).",
                )
            )

        # 6. High-Confidence Threat Indicators
        all_iocs = set()
        for a in alerts:
            if a.indicators:
                all_iocs.update(a.indicators)
        if all_iocs:
            factors.append(
                ScoreFactorBreakdown(
                    factor="Threat Indicators",
                    points=settings.INDICATOR_THREAT_BONUS,
                    value=len(all_iocs),
                    reason=f"Incident associates with {len(all_iocs)} unique indicators of compromise (+{settings.INDICATOR_THREAT_BONUS:.1f} pts).",
                )
            )

        # Calculate final total score (capped at 100.0)
        total_points = sum(f.points for f in factors)
        final_score = min(100.0, max(0.0, round(total_points, 1)))

        # Determine priority level based on strict thresholds
        if final_score >= settings.CRITICAL_THRESHOLD:
            priority = IncidentPriority.CRITICAL
        elif final_score >= settings.HIGH_THRESHOLD:
            priority = IncidentPriority.HIGH
        elif final_score >= settings.MEDIUM_THRESHOLD:
            priority = IncidentPriority.MEDIUM
        elif final_score >= settings.LOW_THRESHOLD:
            priority = IncidentPriority.LOW
        else:
            priority = IncidentPriority.INFORMATIONAL

        return PrioritizationResult(
            score=final_score,
            priority=priority,
            factors=factors,
            conservative_defaults=conservative_notes,
        )
