"""Chronological timeline builder for incident evidence."""

from typing import List
from app.models.alert import AlertModel
from app.schemas.analysis import TimelineEvent


def build_chronological_timeline(alerts: List[AlertModel]) -> List[TimelineEvent]:
    """Construct an ordered timeline of events directly grounded in telemetry alerts."""
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
    timeline: List[TimelineEvent] = []

    for alert in sorted_alerts:
        entities = {}
        if alert.user_entity:
            entities["user"] = alert.user_entity
        if alert.host_entity:
            entities["host"] = alert.host_entity
        if alert.source_ip:
            entities["source_ip"] = alert.source_ip
        if alert.destination_ip:
            entities["destination_ip"] = alert.destination_ip
        if alert.destination_port:
            entities["destination_port"] = alert.destination_port
        if alert.indicators:
            entities["indicators"] = alert.indicators

        desc = alert.title
        if alert.description and alert.description != alert.title:
            desc = f"{alert.title}: {alert.description}"

        timeline.append(
            TimelineEvent(
                timestamp=alert.timestamp,
                alert_id=alert.id,
                source_event_id=alert.source_event_id,
                event_type=alert.event_type,
                source=alert.source,
                summary=desc,
                entities=entities,
            )
        )

    return timeline
