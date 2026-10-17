"""Deterministic evidence synthesis engine separating observed facts from hypotheses."""

from typing import List, Set
from app.analysis.timeline import build_chronological_timeline
from app.models.alert import AlertModel
from app.models.incident import IncidentModel
from app.schemas.analysis import StructuredIncidentAnalysis


class DeterministicSynthesizer:
    """Produces grounded incident summaries without external LLM dependencies."""

    @classmethod
    def synthesize(
        cls, incident: IncidentModel, alerts: List[AlertModel]
    ) -> StructuredIncidentAnalysis:
        """Synthesize facts, timeline, hypotheses, and recommendations from alerts."""
        if not alerts:
            return StructuredIncidentAnalysis(
                concise_summary="No alerts associated with this incident.",
                supporting_alert_ids=[],
                observed_facts=["Zero alerts recorded for this incident."],
                inferred_hypotheses=["No evidence available to formulate hypotheses."],
                chronological_timeline=[],
                recommended_actions=["Review incident creation metadata."],
                is_validated=True,
                validation_warnings=[],
            )

        # Sort alerts chronologically
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        timeline = build_chronological_timeline(sorted_alerts)
        supporting_alert_ids = [a.id for a in sorted_alerts]

        # 1. Observed Facts (strictly empirical statements citing Alert IDs)
        observed_facts: List[str] = []
        event_types: Set[str] = set()
        all_indicators: Set[str] = set()
        affected_hosts: Set[str] = set()
        affected_users: Set[str] = set()

        for a in sorted_alerts:
            event_types.add(a.event_type)
            if a.host_entity:
                affected_hosts.add(a.host_entity)
            if a.user_entity:
                affected_users.add(a.user_entity)
            if a.indicators:
                all_indicators.update(a.indicators)

            entity_details = []
            if a.host_entity:
                entity_details.append(f"host='{a.host_entity}'")
            if a.user_entity:
                entity_details.append(f"user='{a.user_entity}'")
            if a.source_ip:
                entity_details.append(f"src_ip={a.source_ip}")
            if a.destination_ip:
                entity_details.append(f"dst_ip={a.destination_ip}")
            if a.destination_port:
                entity_details.append(f"dst_port={a.destination_port}")

            entities_str = ", ".join(entity_details) if entity_details else "unspecified entities"
            iocs_str = f" Indicators: {', '.join(a.indicators)}" if a.indicators else ""

            fact = (
                f"[Alert {a.id} | {a.source} ({a.source_event_id})] at {a.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}: "
                f"Observed '{a.event_type}' ({a.title}) involving {entities_str}. Severity={a.severity}, Confidence={a.confidence:.2f}.{iocs_str}"
            )
            observed_facts.append(fact)

        # 2. Inferred Hypotheses (distinctly labeled as hypotheses)
        hypotheses: List[str] = []
        lower_types = {t.lower() for t in event_types}

        if any("brute" in t for t in lower_types) and any("priv" in t for t in lower_types):
            users_str = ", ".join(affected_users) if affected_users else "the affected account"
            hypotheses.append(
                f"Hypothesis: Attacker may have achieved initial access via credential stuffing/brute force, followed by privilege escalation on {users_str}."
            )

        if any("c2" in t or "beacon" in t for t in lower_types):
            hosts_str = ", ".join(affected_hosts) if affected_hosts else "the target asset"
            hypotheses.append(
                f"Hypothesis: Active command-and-control channel established from {hosts_str}, indicating potential remote adversary persistence."
            )

        if any("exfil" in t or "unauthorizedaccess" in t for t in lower_types):
            hypotheses.append(
                "Hypothesis: Potential data staging or exfiltration activity across external network boundaries."
            )

        if any("process" in t or "powershell" in t or "script" in t for t in lower_types):
            hypotheses.append(
                "Hypothesis: Malicious execution of native system utilities (Living-off-the-Land / LOLBins) to evade signature detection."
            )

        if not hypotheses:
            hypotheses.append(
                f"Hypothesis: Activity pattern represents anomalous {', '.join(event_types)} behavior requiring correlation with endpoint process telemetry."
            )

        # 3. Recommended Actions
        actions: List[str] = []
        if affected_hosts:
            actions.append(
                f"Isolate host(s) {', '.join(affected_hosts)} from the corporate network pending forensic memory triage."
            )
        if affected_users:
            actions.append(
                f"Force credential reset and revoke active SSO/Kerberos sessions for user(s) {', '.join(affected_users)}."
            )
        if all_indicators:
            actions.append(
                f"Query perimeter firewalls and proxy logs for indicator(s): {', '.join(list(all_indicators)[:5])}."
            )
        actions.append(
            f"Review surrounding telemetry +/- 60 minutes around {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} for unflagged lateral movement."
        )

        # 4. Concise Summary
        time_span = (
            f"from {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')} to {incident.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}"
            if incident.first_seen != incident.last_seen
            else f"at {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        hosts_desc = f" affecting host(s) {', '.join(affected_hosts)}" if affected_hosts else ""
        users_desc = f" involving user(s) {', '.join(affected_users)}" if affected_users else ""
        concise_summary = (
            f"Incident {incident.id} ({incident.priority} priority, score {incident.score:.1f}/100) comprises "
            f"{len(alerts)} correlated alert(s) {time_span}{hosts_desc}{users_desc}. "
            f"Observed event categories: {', '.join(sorted(event_types))}."
        )

        return StructuredIncidentAnalysis(
            concise_summary=concise_summary,
            supporting_alert_ids=supporting_alert_ids,
            observed_facts=observed_facts,
            inferred_hypotheses=hypotheses,
            chronological_timeline=timeline,
            recommended_actions=actions,
            is_validated=True,
            validation_warnings=[],
        )
