"""JSON alert ingestion processor."""

import json
from typing import Any, Dict, List, Tuple, Union
from app.ingestion.normalizer import normalize_batch, normalize_record
from app.schemas.alert import CanonicalAlert, IngestionErrorDetail


def parse_and_normalize_json(
    payload: Union[str, bytes, Dict[str, Any], List[Dict[str, Any]]]
) -> Tuple[List[CanonicalAlert], List[IngestionErrorDetail]]:
    """Parse raw JSON input (string, dict, or list) into normalized canonical alerts."""
    if isinstance(payload, (str, bytes)):
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as e:
            return [], [
                IngestionErrorDetail(
                    item_index=0,
                    raw_data={"input_preview": str(payload)[:200]},
                    errors=[f"Invalid JSON syntax: {e.msg} at line {e.lineno} col {e.colno}"],
                )
            ]
    else:
        parsed = payload

    if isinstance(parsed, dict):
        parsed = [parsed]
    elif not isinstance(parsed, list):
        return [], [
            IngestionErrorDetail(
                item_index=0,
                raw_data={"type": type(parsed).__name__},
                errors=["Root JSON element must be an object or an array of objects."],
            )
        ]

    return normalize_batch(parsed)
