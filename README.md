# 🛡️ Incident Severity & Escalation Decision Engine

[![Python Version](https://img.shields.io/badge/Python-3.14-blue.svg)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.65+-red.svg)](https://streamlit.io)
[![License: Academic](https://img.shields.io/badge/License-Academic%20Evaluation-green.svg)](#)
[![Tests: Pytest](https://img.shields.io/badge/Tests-Passing%20100%25-brightgreen.svg)](#)

An auditable, explainable cybersecurity decision-support application built for college minor degree evaluation. It processes synthetic security incident telemetry, computes deterministic incident severity, assigns standardized escalation procedures with strict SLAs, and generates an auditable decision trace justifying every triage outcome.

---

## 📌 Project Highlights & Novelty

* **100% Explainable Cyber Triage:** Unlike black-box ML models, this engine produces a complete **Auditable Decision Trace** showing each factor's point contribution, arithmetic formula derivation, and policy justification.
* **Decoupled Declarative Rules:** All scoring weights, asset/confidence brackets, and escalation SOPs reside in `config/rules.yaml`. Security policies can be updated without touching Python code.
* **NIST SP 800-61 Alignment:** Maps directly to Section 3.2.6 (Incident Prioritization) based on Functional Impact, Information Impact, and Threat Persistence.
* **15 Synthetic Tabletop Scenarios:** Built-in scenario lab covering phishing, ransomware, credential stuffing, S3 bucket data leaks, C2 beaconing, and zero-day advisories.
* **Academic Safety:** 100% synthetic data. No offensive tools, exploits, malware, or unauthorized access techniques.

---

## 🗂️ Project Directory Structure

```text
incident-decision-engine/
│
├── app.py                      # Main Streamlit web application & landing hub
├── requirements.txt           # Dependency specifications (Streamlit, PyYAML, Pandas, Pytest)
├── README.md                  # Complete project documentation and setup guide
│
├── config/
│   └── rules.yaml             # Declarative scoring weights, thresholds, and escalation SOPs
│
├── engine/
│   ├── __init__.py
│   ├── validator.py           # Input sanitization and boundary validation
│   ├── trace.py               # Auditable decision trace data models and serialization
│   └── rules_engine.py        # Core scoring, severity classification, and escalation logic
│
├── database/
│   ├── __init__.py
│   └── db_manager.py          # SQLite database CRUD operations and summary analytics
│
├── data/
│   ├── __init__.py
│   └── synthetic_cases.py     # 15 realistic synthetic cyber incident scenarios
│
├── pages/
│   ├── 1_📊_Dashboard.py         # Real-time KPIs, severity charts, and recent activity feed
│   ├── 2_🔍_Analyze_Incident.py  # Interactive incident triage form & live decision trace card
│   ├── 3_📜_Incident_History.py   # Filterable audit log, CSV export, and deep trace inspector
│   ├── 4_📐_Severity_Matrix.py    # Visual scoring rubrics, math formulation, and SOP guide
│   ├── 5_🧪_Tabletop_Testing.py   # Simulation lab: batch test runner for the 15 synthetic cases
│   └── 6_💡_About_Project.py      # Architecture documentation, viva defense notes, and FAQs
│
├── docs/
│   └── VIVA_GUIDE.md          # College viva defense cheat sheet with model examiner Q&A
│
└── tests/
    ├── __init__.py
    ├── test_rules_engine.py   # Unit tests for scoring logic & boundary transitions
    ├── test_trace.py          # Unit tests for decision trace data integrity
    ├── test_validator.py      # Unit tests for input validation
    ├── test_database.py       # Unit tests for SQLite persistence
    └── test_synthetic_cases.py# Automated verification of all 15 synthetic tabletop cases
```

---

## 🧮 Scoring Formulation & Escalation Framework

### 1. Factor Weighting Rubric
$$\text{Total Score} = S_{\text{impact}} + S_{\text{assets}} + S_{\text{confidence}} + S_{\text{persistence}} + S_{\text{exposure}} \quad (\text{Range: } 1 \text{ to } 15)$$

| Factor | Value / Bracket | Score Contribution | Operational Rationale |
| :--- | :--- | :---: | :--- |
| **Business Impact** | Low<br>Medium<br>High<br>Critical | +1<br>+2<br>+3<br>+4 | Minimal interruption<br>Secondary workflow degradation<br>Core client-facing service outage<br>Catastrophic enterprise infrastructure failure |
| **Affected Assets** | 1–2 assets<br>3–10 assets<br>11–25 assets<br>26+ assets | +0<br>+1<br>+2<br>+3 | Contained to single workstation<br>Subnet / departmental blast radius<br>Multi-zone network impact<br>Enterprise-wide compromise |
| **Detection Confidence** | < 50%<br>50–74%<br>75–89%<br>90–100% | +0<br>+1<br>+2<br>+3 | Uncorroborated / noisy sensor alert<br>Preliminary single-sensor signal<br>Corroborated across multiple security tools<br>Definitive forensic evidence / confirmed indicator |
| **Persistence** | No<br>Yes | +0<br>+2 | Ephemeral / in-memory only<br>Survives reboot via registry, cron, service |
| **Data Exposure** | No<br>Yes | +0<br>+3 | No sensitive data accessed<br>Confirmed compromise or exfiltration of sensitive/PII data |

### 2. Severity Tiers & SOP Escalation Mappings

| Composite Score | Severity Level | Escalation Protocol | SLA Response Window | Key Operational Directive |
| :---: | :---: | :--- | :---: | :--- |
| **0 – 2** | **LOW** | **Normal Monitoring** | Within 24 hours | Log event in SIEM, retain telemetry, no manual call-out. |
| **3 – 5** | **MEDIUM** | **Security Analyst Review** | Within 4 hours | Assign to Tier-1/Tier-2 analyst for artifact triage & host isolation. |
| **6 – 8** | **HIGH** | **Incident Response Team** | Within 1 hour | Mobilize CSIRT, enact network segment containment, initiate forensic dump. |
| **9+** | **CRITICAL** | **Immediate Escalation** | < 15 minutes | Declare Major Incident, page CISO, convene executive crisis bridge. |

---

## 🚀 Quickstart & Installation Guide

### Prerequisites
* Python 3.10+ (tested on Python 3.14 on macOS)
* pip package manager

### 1. Setup Virtual Environment
```bash
cd incident-decision-engine
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Automated Test Suite
Verify that all unit tests and 15 synthetic cases pass:
```bash
./venv/bin/pytest tests/ -v
```

### 3. Launch the Streamlit Web Application
```bash
./venv/bin/streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 📝 Auditable Decision Trace Example

When an incident is evaluated, the system outputs an auditable decision trace:

```text
Incident ID: INC-20261003-9182
Title: Enterprise Ransomware Outbreak with Exfiltration
Severity: CRITICAL (15 Points)
Escalation: Immediate Escalation (< 15 min SLA)

Factor Attribution:
- Business Impact: Critical (+4 pts) -> Catastrophic enterprise infrastructure failure
- Affected Assets: 45 assets (+3 pts) -> Enterprise-wide compromise (26+ assets)
- Detection Confidence: 98% (+3 pts) -> Definitive forensic verification (90-100%)
- Persistence: Yes (+2 pts) -> Persistent scheduled service detected
- Data Exposure: Yes (+3 pts) -> Confirmed exfiltration to external leak site

Formula: 4 + 3 + 3 + 2 + 3 = 15 points
Directive: Declare Major Incident. Page on-call CISO and initiate executive crisis bridge.
```

---

## 🎓 College Viva Voce Defense

For comprehensive viva talking points, architecture defense, and examiner Q&A, refer to:
* **[docs/VIVA_GUIDE.md](docs/VIVA_GUIDE.md)**
* Or open the **💡 About Project** page inside the running Streamlit web application.
