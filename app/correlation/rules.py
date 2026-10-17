"""Correlation rules for linking security alerts to incidents."""

from datetime import timedelta
from typing import Optional, Set
from app.models.alert import AlertModel
from app.models.incident import IncidentModel


def is_within_time_window(alert: AlertModel, incident: IncidentModel, window_minutes: int) -> bool:
    """Check if the alert timestamp falls within the sliding time window of the incident."""
    if not alert.timestamp or not incident.first_seen or not incident.last_seen:
        return False

    window = timedelta(minutes=window_minutes)
    window_start = incident.first_seen - window
    window_end = incident.last_seen + window

    return window_start <= alert.timestamp <= window_end


def match_host_pivot(alert: AlertModel, incident: IncidentModel) -> Optional[str]:
    """Correlate if alert and incident target the same host."""
    if not alert.host_entity:
        return None
    alert_host = alert.host_entity.lower().strip()

    if incident.primary_host and incident.primary_host.lower().strip() == alert_host:
        return f"HOST_MATCH: {alert_host}"

    # Also check existing linked alerts
    for link in incident.alert_links:
        if link.alert and link.alert.host_entity:
            if link.alert.host_entity.lower().strip() == alert_host:
                return f"HOST_MATCH: {alert_host}"

    return None


def match_user_pivot(alert: AlertModel, incident: IncidentModel) -> Optional[str]:
    """Correlate if alert and incident involve the same compromised account."""
    if not alert.user_entity:
        return None
    alert_user = alert.user_entity.lower().strip()

    if incident.primary_user and incident.primary_user.lower().strip() == alert_user:
        return f"USER_MATCH: {alert_user}"

    for link in incident.alert_links:
        if link.alert and link.alert.user_entity:
            if link.alert.user_entity.lower().strip() == alert_user:
                return f"USER_MATCH: {alert_user}"

    return None


def match_indicator_pivot(alert: AlertModel, incident: IncidentModel) -> Optional[str]:
    """Correlate if alert shares indicators of compromise (IOCs) with the incident."""
    if not alert.indicators:
        return None

    alert_iocs: Set[str] = {str(i).lower().strip() for i in alert.indicators if str(i).strip()}
    if not alert_iocs:
        return None

    incident_iocs: Set[str] = {
        str(i).lower().strip() for i in (incident.correlated_indicators or []) if str(i).strip()
    }

    # Also check IOCs from linked alerts
    for link in incident.alert_links:
        if link.alert and link.alert.indicators:
            for i in link.alert.indicators:
                incident_iocs.add(str(i).lower().strip())

    intersection = alert_iocs.intersection(incident_iocs)
    if intersection:
        return f"IOC_MATCH: {', '.join(sorted(list(intersection))[:3])}"

    return None


def evaluate_alert_correlation(
    alert: AlertModel, incident: IncidentModel, window_minutes: int
) -> Optional[str]:
    """Evaluate whether an alert correlates with an active incident.
    
    Returns the correlation rationale string if correlated, or None.
    """
    if not is_within_time_window(alert, incident, window_minutes):
        return None

    # Priority 1: Host match
    host_reason = match_host_pivot(alert, incident)
    if host_reason:
        return host_reason

    # Priority 2: User match
    user_reason = match_user_pivot(alert, incident)
    if user_reason:
        return user_reason

    # Priority 3: IOC match
    ioc_reason = match_indicator_pivot(alert, incident)
    if ioc_reason:
        return ioc_reason

    return None
