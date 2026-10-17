"""Alert normalization and validation pipeline."""

from typing import Any, Dict, List, Tuple
import logging
from app.schemas.alert import CanonicalAlert, IngestionErrorDetail

logger = logging.getLogger("security_triage.ingestion")


def normalize_record(raw: Dict[str, Any], index: int = 0) -> Tuple[CanonicalAlert | None, IngestionErrorDetail | None]:
    """Validate and normalize a single raw record into a CanonicalAlert.
    
    Returns (alert, None) on success, or (None, error_detail) on failure.
    """
    if not isinstance(raw, dict):
        return None, IngestionErrorDetail(
            item_index=index,
            raw_data={"non_dict_input": str(raw)},
            errors=["Alert item must be a JSON object / dictionary."],
        )

    # Reject completely empty records
    if not any(k for k, v in raw.items() if v is not None and str(v).strip() != ""):
        return None, IngestionErrorDetail(
            item_index=index,
            raw_data=raw,
            errors=["Alert item contains only empty or null fields."],
        )

    try:
        alert = CanonicalAlert.from_raw(raw)
        return alert, None
    except Exception as e:
        logger.warning("Failed to normalize alert at index %d: %s", index, str(e))
        return None, IngestionErrorDetail(
            item_index=index,
            raw_data=raw,
            errors=[str(e)],
        )


def normalize_batch(records: List[Dict[str, Any]]) -> Tuple[List[CanonicalAlert], List[IngestionErrorDetail]]:
    """Normalize a batch of raw records with error isolation.
    
    A malformed record does not stop valid records from being processed.
    """
    valid_alerts: List[CanonicalAlert] = []
    errors: List[IngestionErrorDetail] = []

    for idx, item in enumerate(records):
        alert, err = normalize_record(item, index=idx)
        if alert is not None:
            valid_alerts.append(alert)
        elif err is not None:
            errors.append(err)

    return valid_alerts, errors
