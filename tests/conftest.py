"""Pytest fixtures for unit and integration testing."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base
from app.models import alert, incident, summary  # noqa: F401


@pytest.fixture(scope="function")
def db_session():
    """Create a fresh in-memory SQLite database session for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def sample_json_alert():
    """Return a representative single alert dictionary."""
    return {
        "source_event_id": "EDR-99120",
        "source": "CrowdStrike",
        "timestamp": "2026-10-17T09:30:00Z",
        "event_type": "SuspiciousProcess",
        "severity": "HIGH",
        "confidence": 0.85,
        "user": "jdoe",
        "host": "wkstn-042.corp",
        "asset_criticality": "MEDIUM",
        "source_ip": "192.168.1.105",
        "destination_ip": "198.51.100.24",
        "destination_port": 443,
        "indicators": ["powershell.exe -enc AAAA...", "198.51.100.24", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        "title": "Encoded PowerShell Execution",
        "description": "Detected base64 encoded PowerShell script executing from user AppData.",
    }


@pytest.fixture
def sample_csv_data():
    """Return raw CSV text with standard and edge-case rows."""
    return """source_event_id,source,timestamp,event_type,severity,confidence,user,host,asset_criticality,indicators
CSV-001,Firewall,2026-10-17T10:00:00Z,PortScan,LOW,0.6,scanner,edge-gw-01,HIGH,"10.0.0.5, 10.0.0.6"
CSV-002,Okta,2026-10-17T10:05:00Z,MFAExhaustion,HIGH,0.9,admin,idp-prod,TIER_1_CRITICAL,198.51.100.55
CSV-003,Suricata,2026-10-17T10:10:00Z,C2Beaconing,CRITICAL,95,admin,wkstn-042.corp,HIGH,evil-c2.example.com
"""
