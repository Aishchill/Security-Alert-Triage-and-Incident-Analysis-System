"""Ingestion module init."""

from app.ingestion.normalizer import normalize_record, normalize_batch
from app.ingestion.json_ingest import parse_and_normalize_json
from app.ingestion.csv_ingest import parse_and_normalize_csv

__all__ = [
    "normalize_record",
    "normalize_batch",
    "parse_and_normalize_json",
    "parse_and_normalize_csv",
]
