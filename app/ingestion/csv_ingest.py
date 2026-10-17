"""CSV alert ingestion processor."""

import csv
import io
from typing import Any, Dict, List, Tuple, Union
from app.ingestion.normalizer import normalize_record
from app.schemas.alert import CanonicalAlert, IngestionErrorDetail


def parse_and_normalize_csv(
    csv_content: Union[str, bytes]
) -> Tuple[List[CanonicalAlert], List[IngestionErrorDetail]]:
    """Parse CSV text or bytes into normalized canonical alerts with row-level error reporting."""
    if isinstance(csv_content, bytes):
        try:
            text = csv_content.decode("utf-8-sig")  # Handles UTF-8 BOM if present
        except UnicodeDecodeError:
            text = csv_content.decode("latin-1", errors="replace")
    else:
        text = csv_content

    reader = csv.reader(io.StringIO(text))
    try:
        header_row = next(reader)
    except StopIteration:
        return [], [
            IngestionErrorDetail(
                item_index=0,
                raw_data=None,
                errors=["CSV content is empty."],
            )
        ]

    # Clean headers (strip, lower, remove BOM artifacts)
    headers = [h.strip().lower().replace(" ", "_").replace("-", "_") for h in header_row]
    if not any(headers):
        return [], [
            IngestionErrorDetail(
                item_index=0,
                raw_data={"headers": header_row},
                errors=["CSV headers cannot be completely empty."],
            )
        ]

    valid_alerts: List[CanonicalAlert] = []
    errors: List[IngestionErrorDetail] = []

    for row_idx, row in enumerate(reader, start=2):
        # Skip completely blank lines
        if not row or not any(field.strip() for field in row):
            continue

        # Map row to dict
        record: Dict[str, Any] = {}
        for col_idx, header in enumerate(headers):
            if col_idx < len(row):
                val = row[col_idx].strip()
                record[header] = val if val != "" else None
            else:
                record[header] = None

        alert, err = normalize_record(record, index=row_idx)
        if alert is not None:
            valid_alerts.append(alert)
        elif err is not None:
            errors.append(err)

    return valid_alerts, errors
