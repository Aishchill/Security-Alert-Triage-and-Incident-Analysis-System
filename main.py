"""Main entry point CLI for the Security Alert Triage and Incident Analysis System."""

import argparse
import json
import os
import subprocess
import sys
import uvicorn
from app.correlation.engine import CorrelationEngine
from app.database import SessionLocal, init_db
from app.ingestion.json_ingest import parse_and_normalize_json
from app.services.alert_service import AlertService


def seed_synthetic_data():
    """Populate database with synthetic attack scenarios."""
    init_db()
    data_path = os.path.join(os.path.dirname(__file__), "data", "synthetic_alerts.json")
    if not os.path.exists(data_path):
        print(f"Error: synthetic alerts file not found at {data_path}")
        return

    with open(data_path, "r", encoding="utf-8") as f:
        synthetic_records = json.load(f)

    db = SessionLocal()
    try:
        alerts, errors = parse_and_normalize_json(synthetic_records)
        saved, dupes = AlertService.save_alerts_batch(db, alerts)
        created, updated = CorrelationEngine.correlate_batch(db, saved)
        print(f"[*] Synthetic alerts seeded successfully:")
        print(f"    - Processed: {len(synthetic_records)} records")
        print(f"    - Persisted: {len(saved)} alerts ({dupes} duplicates skipped)")
        print(f"    - Created Incidents: {len(created)} ({', '.join(created)})")
        print(f"    - Updated Incidents: {len(updated)} ({', '.join(updated)})")
        if errors:
            print(f"    - Ingestion Errors: {len(errors)}")
    finally:
        db.close()


def run_api(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """Start the FastAPI REST API server."""
    print(f"[*] Starting Security Triage REST API on port {port}")
    print(f"[*] OpenAPI Documentation available at:")
    print(f"    - http://127.0.0.1:{port}/docs")
    print(f"    - http://localhost:{port}/docs")
    uvicorn.run("app.api.app:app", host=host, port=port, reload=reload)


def run_dashboard(port: int = 8501):
    """Start the Streamlit Analyst Interface."""
    dashboard_path = os.path.join(os.path.dirname(__file__), "app", "dashboard", "app.py")
    print(f"[*] Starting Streamlit Analyst Dashboard at http://localhost:{port}")
    cmd = [sys.executable, "-m", "streamlit", "run", dashboard_path, "--server.port", str(port)]
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(
        description="Security Alert Triage and Incident Analysis System CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # API command
    api_parser = subparsers.add_parser("api", help="Launch FastAPI REST server")
    api_parser.add_argument("--host", default="0.0.0.0", help="Binding host")
    api_parser.add_argument("--port", type=int, default=8000, help="Binding port")
    api_parser.add_argument("--reload", action="store_true", help="Auto reload on changes")

    # Dashboard command
    dash_parser = subparsers.add_parser("dashboard", help="Launch Streamlit Analyst Interface")
    dash_parser.add_argument("--port", type=int, default=8501, help="Binding port")

    # Seed command
    subparsers.add_parser("seed", help="Seed database with synthetic alert scenarios")

    # Test command
    subparsers.add_parser("test", help="Run pytest automated test suite")

    args = parser.parse_args()

    if args.command == "api":
        run_api(host=args.host, port=args.port, reload=args.reload)
    elif args.command == "dashboard":
        run_dashboard(port=args.port)
    elif args.command == "seed":
        seed_synthetic_data()
    elif args.command == "test":
        subprocess.run([sys.executable, "-m", "pytest", "-v"])
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
