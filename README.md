# Security Alert Triage and Incident Analysis System

An enterprise-grade, explainable security monitoring application built for modern Security Operations Centers (SOC). The system ingests disparate telemetry alerts (JSON/CSV), normalizes records into canonical schemas, correlates related events into incidents using configurable sliding time windows and pivot rules, calculates explainable priority scores deterministically, and synthesizes factual, evidence-grounded incident summaries.

---

## 🌟 Key Capabilities

- **Multi-Format Ingestion**: Ingests JSON (single alert or array) and CSV data with robust normalization, tolerant parsing of disparate field names, and row-level error isolation.
- **Idempotency & Deduplication**: Cryptographic event fingerprinting (`SHA-256`) eliminates duplicate alerts and prevents duplicate incident creation.
- **Preserved Forensics**: Original, unaltered raw logs are retained immutably in SQLite/JSON for forensic audits.
- **Pivot-Based Correlation**: Clusters related events across sliding time windows (default: 60 minutes) based on shared host, account, network indicators (IOCs), and tactical attack stages.
- **Explainable Prioritization (No Black Box)**: 100% deterministic mathematical scoring engine (0–100) factoring in base severity, telemetry confidence, asset criticality tier, attack chain progression, privileged accounts, and known threat indicators. Returns factor-by-factor point breakdowns and conservative default audits.
- **Evidence-Grounded Incident Analysis**: Strict bifurcation between **Observed Empirical Facts** (every fact explicitly cites supporting Alert IDs) and **Inferred Hypotheses** (attack objectives clearly segregated from facts).
- **Anti-Hallucination & Prompt Injection Defenses**: When optional LLMs are engaged, raw logs are treated as untrusted and defanged. A post-processing Grounding Validator asserts that every cited ID and IOC exists in the database.
- **Analyst Web Interface**: Built with Streamlit for incident triage, search, priority inspection, forensic review, timeline visualization, and manual sandbox ingestion.
- **RESTful API**: FastAPI with OpenAPI documentation, pagination, filtering, status transition tracking, and health metrics.

---

## 🛠️ Technology Stack

- **Python**: 3.11+
- **REST API**: FastAPI + Uvicorn
- **Data Validation & DTOs**: Pydantic v2
- **Persistence & ORM**: SQLAlchemy 2.0
- **Database**: SQLite (WAL mode, foreign key enforcement)
- **Analyst Interface**: Streamlit + Pandas
- **Automated Testing**: pytest (26 unit & integration tests)

---

## Deployment link1 https://security-alert-triage-and-incident-c0f1.onrender.com/docs
 

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.11+ installed (`python --version` or `py -3.11 --version`)

### 2. Environment Setup
```bash
# Clone or navigate to directory
cd first1

# Create virtual environment
py -3.11 -m venv .venv

# Activate virtual environment
# Windows:
.\.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Automated Tests
```bash
pytest -v
```
All 26 test suites cover ingestion, normalization, deduplication, correlation, scoring determinism, evidence grounding, and REST endpoints.

### 4. Seed Synthetic Security Scenarios
```bash
python main.py seed
```
Loads multi-stage attack scenarios (Credential stuffing, Kerberoasting, LSASS dumping on Domain Controller, Phishing, PowerShell execution, and Cobalt Strike C2 beaconing).

### 5. Launch the REST API
```bash
python main.py api --port 8000
```
- API Base URL: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

### 6. Launch the Streamlit Analyst Interface
In a separate terminal:
```bash
python main.py dashboard --port 8501
```
Open your browser to `http://localhost:8501`.

---



### Ingestion Example (cURL)
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/alerts/ingest/json" \
     -H "Content-Type: application/json" \
     -d '{
       "source_event_id": "EDR-1001",
       "source": "CrowdStrike",
       "event_type": "SuspiciousProcess",
       "severity": "HIGH",
       "confidence": 0.85,
       "user": "jdoe",
       "host": "wkstn-01.corp",
       "indicators": ["powershell.exe", "198.51.100.24"],
       "title": "Encoded PowerShell execution"
     }'
```

---

## 📊 Explainable Prioritization Breakdown

The scoring engine calculates an incident score between `0.0` and `100.0` through deterministic summation:

1. **Base Severity Factor** (Max alert severity in incident):
   - CRITICAL: +45.0 pts
   - HIGH: +34.0 pts
   - MEDIUM: +22.0 pts
   - LOW: +12.0 pts
   - INFORMATIONAL: +5.0 pts
2. **Telemetry Confidence Factor**:
   - `mean(confidence) * 15.0 pts` (Conservative default 0.5 = +7.5 pts if missing)
3. **Asset Criticality Factor** (Max tier among affected assets):
   - TIER_1_CRITICAL: +25.0 pts
   - HIGH: +18.0 pts
   - MEDIUM: +10.0 pts (Conservative default if missing)
   - LOW: +5.0 pts
4. **Multi-Stage Attack Chain Progression**:
   - `+5.0 pts` per distinct attack stage beyond the first (Max: +15.0 pts)
5. **Privileged Account Exposure**:
   - `+10.0 pts` if account matches high-value list (`admin`, `root`, `system`, etc.)
6. **Threat Indicator Bonus**:
   - `+10.0 pts` if correlated indicators (IOCs) are observed

**Thresholds:**
- **CRITICAL**: Score $\ge 80.0$
- **HIGH**: $60.0 \le \text{Score} < 80.0$
- **MEDIUM**: $40.0 \le \text{Score} < 60.0$
- **LOW**: $20.0 \le \text{Score} < 40.0$
- **INFORMATIONAL**: $\text{Score} < 20.0$

---

## 🛡️ Security & Reliability Controls

- **Forensic Immutability**: Raw alert payloads are preserved unmodified as JSON for legal and forensic compliance.
- **Audit Trails**: Every incident status transition generates an immutable `IncidentStatusHistoryModel` entry containing the previous status, new status, analyst identity, timestamp, and rationale.
- **Untrusted Input Protection**: Incoming raw telemetry is treated as untrusted data. Special character defanging and length bounding neutralize indirect prompt injection attempts.
- **Anti-Hallucination Grounding Validator**: Validates that any LLM summary only references real alert IDs and IOCs present in the database.
- **Conservative Handling of Missing Data**: Incomplete records default conservatively (MEDIUM asset tier, 0.5 confidence) and explicitly log a conservative default note in the score breakdown.
