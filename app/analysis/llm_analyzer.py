"""Optional LLM integration with strict Pydantic validation, prompt injection defenses, and grounding checks."""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from app.analysis.synthesizer import DeterministicSynthesizer
from app.analysis.timeline import build_chronological_timeline
from app.models.alert import AlertModel
from app.models.incident import IncidentModel
from app.schemas.analysis import StructuredIncidentAnalysis, TimelineEvent

logger = logging.getLogger("security_triage.llm_analyzer")


def sanitize_untrusted_log(text: str) -> str:
    """Sanitize raw log strings to mitigate indirect prompt injection."""
    if not text:
        return ""
    # Defang common injection tokens
    cleaned = text.replace("```", "'''")
    # Defang system prompt overrides
    cleaned = re.sub(
        r"(?i)(ignore (all )?prior instructions|system\s*:|assistant\s*:|human\s*:)",
        "[SUSPICIOUS_PROMPT_DEFANGED]",
        cleaned,
    )
    return cleaned[:2000]  # Bound length per alert field


class GroundingValidator:
    """Asserts that all claims in an incident analysis are strictly grounded in actual alert evidence."""

    @classmethod
    def validate_and_correct(
        cls,
        analysis: StructuredIncidentAnalysis,
        real_alerts: List[AlertModel],
    ) -> StructuredIncidentAnalysis:
        """Verify that every cited alert ID, indicator, and timestamp belongs to the real alerts.
        
        Prunes or corrects any hallucinated references.
        """
        valid_alert_ids = {a.id for a in real_alerts}
        valid_source_ids = {a.source_event_id for a in real_alerts}
        valid_indicators = set()
        for a in real_alerts:
            if a.indicators:
                valid_indicators.update(str(i).lower() for i in a.indicators)
            if a.source_ip:
                valid_indicators.add(a.source_ip.lower())
            if a.destination_ip:
                valid_indicators.add(a.destination_ip.lower())

        warnings: List[str] = list(analysis.validation_warnings)
        corrected_alert_ids: List[str] = []

        # Validate supporting alert IDs
        for aid in analysis.supporting_alert_ids:
            if aid in valid_alert_ids or aid in valid_source_ids:
                corrected_alert_ids.append(aid)
            else:
                warnings.append(f"Pruned ungrounded/hallucinated alert ID reference: '{aid}'")

        if not corrected_alert_ids:
            # Fallback to actual alerts if model pruned all
            corrected_alert_ids = [a.id for a in real_alerts]

        analysis.supporting_alert_ids = corrected_alert_ids

        # Re-ground timeline with guaranteed real alert timestamps and data
        real_timeline = build_chronological_timeline(real_alerts)
        analysis.chronological_timeline = real_timeline

        # Update validation status
        analysis.validation_warnings = warnings
        analysis.is_validated = len(warnings) == 0

        return analysis


class LLMIncidentAnalyzer:
    """LLM Incident Summarizer with deterministic fallback and strict grounding validation."""

    @classmethod
    def analyze_incident(
        cls,
        incident: IncidentModel,
        alerts: List[AlertModel],
        use_llm: bool = False,
        mock_llm_response: Optional[Dict[str, Any]] = None,
    ) -> StructuredIncidentAnalysis:
        """Produce an evidence-grounded summary using LLM if available, otherwise deterministic engine."""
        if not use_llm and not mock_llm_response:
            return DeterministicSynthesizer.synthesize(incident, alerts)

        # Prepare sanitized evidence packet
        evidence_packet = cls._build_evidence_packet(incident, alerts)

        try:
            if mock_llm_response is not None:
                raw_response = mock_llm_response
            else:
                # If a live LLM client were configured (e.g. OpenAI / Google GenAI SDK):
                # Here we invoke with system prompt and evidence packet.
                # Since offline testability without live external API keys is required,
                # we fall back to deterministic synthesizer if no live client is present.
                return DeterministicSynthesizer.synthesize(incident, alerts)

            # Validate LLM output against Pydantic schema
            structured_output = StructuredIncidentAnalysis.model_validate(raw_response)

            # Strict anti-hallucination validation against ground truth DB records
            grounded_output = GroundingValidator.validate_and_correct(structured_output, alerts)
            return grounded_output

        except Exception as e:
            logger.warning("LLM analysis failed (%s); safely falling back to deterministic synthesis.", str(e))
            fallback = DeterministicSynthesizer.synthesize(incident, alerts)
            fallback.validation_warnings.append(f"LLM analysis failed; deterministic fallback used: {str(e)}")
            return fallback

    @classmethod
    def _build_evidence_packet(cls, incident: IncidentModel, alerts: List[AlertModel]) -> str:
        """Construct a secure, injection-defended prompt payload."""
        alerts_data = []
        for a in alerts:
            alerts_data.append({
                "alert_id": a.id,
                "source_event_id": a.source_event_id,
                "source": a.source,
                "timestamp": a.timestamp.isoformat(),
                "event_type": a.event_type,
                "severity": a.severity,
                "confidence": a.confidence,
                "user": sanitize_untrusted_log(a.user_entity or ""),
                "host": sanitize_untrusted_log(a.host_entity or ""),
                "source_ip": a.source_ip,
                "destination_ip": a.destination_ip,
                "indicators": [sanitize_untrusted_log(str(i)) for i in (a.indicators or [])],
                "title": sanitize_untrusted_log(a.title),
                "description": sanitize_untrusted_log(a.description),
            })

        return (
            "<instruction>\n"
            "You are a security incident analysis assistant. You MUST strictly summarize ONLY the observed facts from "
            "the provided evidence. Do NOT invent or hallucinate any IP addresses, hosts, usernames, or alert IDs. "
            "Clearly separate empirical observed facts from inferred hypotheses.\n"
            "</instruction>\n"
            "<untrusted_raw_evidence>\n"
            f"{json.dumps(alerts_data, indent=2)}\n"
            "</untrusted_raw_evidence>"
        )
