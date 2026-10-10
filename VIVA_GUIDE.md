# College Viva & Project Defense Guide
## Project: Incident Severity & Escalation Decision Engine
### Academic Minor Degree in Cybersecurity / Computer Science

---

## 1. Quick Project Elevator Pitch
> *"Our project is an auditable cybersecurity decision-support system designed to solve alert fatigue in modern Security Operations Centers (SOCs). By processing incident telemetry through declarative, decoupled YAML rules, the engine deterministically calculates incident severity (LOW, MEDIUM, HIGH, CRITICAL), assigns standardized escalation procedures with strict SLAs, and generates a tamper-evident, human-readable decision trace explaining exactly why each decision was made."*

---

## 2. Key Problem Statement & Industry Motivation
1. **SOC Alert Fatigue:** Enterprise security tools (SIEM, EDR, IDS) generate tens of thousands of alerts daily. Over 60% of SOC analysts suffer from burnout, leading to missed critical alerts.
2. **Inconsistent Human Triage:** Different analysts prioritize identical incidents differently based on fatigue, experience, or shift timing.
3. **Lack of Auditability & Compliance:** Regulatory standards (NIST SP 800-61, ISO 27035, GDPR, NIS2) require organizations to demonstrate *why* an incident was escalated or dismissed.

---

## 3. Top Viva Questions & Model Answers

### Q1: Why use a Rule-Based Engine instead of Machine Learning (ML) or LLMs?
* **Answer:** 
  * **Determinism & Reproducibility:** In cybersecurity crisis response and legal disclosures, the same incident parameters must yield the identical severity classification every single time.
  * **Explainability (XAI):** ML classifiers and LLMs operate as "black boxes" that can hallucinate or fail to provide mathematical justification. Regulators (e.g., GDPR Article 22 on automated decision-making) require a clear "right to explanation."
  * **Auditable Liability:** If a CISO is woken up at 2 AM or an emergency breach notification is filed with data protection authorities, leadership needs an auditable trace of mathematical facts, not a probabilistic guess.

### Q2: How is your system architected? What design patterns did you use?
* **Answer:**
  * **Decoupled Configuration (Separation of Concerns):** All scoring rules, weights, and thresholds reside in `config/rules.yaml`. Security policy managers can update policies without editing or recompiling Python code.
  * **Defensive Validation Layer:** Strict input sanitization in `engine/validator.py` ensures integrity before rule evaluation.
  * **Trace Pattern (Data Transfer Object):** The `DecisionTrace` dataclass captures factor attribution, formula summation, and SOP directives into immutable JSON records.
  * **Repository / Persistence Pattern:** `database/db_manager.py` encapsulates SQLite interactions with parameterized queries to prevent SQL injection.

### Q3: How does your scoring rubric work?
* **Answer:**
  * Total Score is the sum of 5 weighted factors (Range: 1 to 15 points):
    1. **Business Impact:** Low (+1), Medium (+2), High (+3), Critical (+4)
    2. **Affected Assets:** 1–2 (+0), 3–10 (+1), 11–25 (+2), 26+ (+3)
    3. **Detection Confidence:** <50% (+0), 50–74% (+1), 75–89% (+2), 90–100% (+3)
    4. **Threat Persistence:** No (+0), Yes (+2)
    5. **Data Exposure:** No (+0), Yes (+3)
  * Severity Thresholds:
    * **0 – 2:** LOW $\rightarrow$ Normal Monitoring (24h SLA)
    * **3 – 5:** MEDIUM $\rightarrow$ Security Analyst Review (4h SLA)
    * **6 – 8:** HIGH $\rightarrow$ Incident Response Team (1h SLA)
    * **9+:** CRITICAL $\rightarrow$ Immediate Escalation (< 15m SLA)

### Q4: Which cybersecurity framework or standard does this align with?
* **Answer:** It aligns with **NIST Special Publication 800-61 Rev. 2** (*Computer Security Incident Handling Guide*), specifically Section 3.2.6 on **Incident Prioritization**, which mandates scoring based on:
  1. *Functional Impact* (mapped to our Business Impact & Affected Assets)
  2. *Information Impact* (mapped to our Data Exposure)
  3. *Recoverability & Persistence* (mapped to our Persistence flag)

### Q5: How did you validate your application?
* **Answer:**
  * We designed **15 synthetic tabletop cyber incident scenarios** covering phishing, ransomware, DDoS, zero-days, insider threats, and C2 beacons.
  * We built an automated test suite (`pytest`) covering:
    * Unit testing of all scoring weights and boundary conditions (e.g. confidence 49% vs 50%, assets 2 vs 3).
    * Validation failure tests (negative numbers, empty fields).
    * SQLite CRUD and JSON trace integrity.
    * 100% pass verification of all 15 synthetic cases against their mathematical ground truth.

---

## 4. Live Demonstration Script for Examiners
1. **Show Dashboard:** Point out overall incident counts, severity distribution breakdown, and average triage score.
2. **Run Tabletop Testing:** Click the Tabletop Testing page, run the 15 synthetic test cases, and show the examiner that all 15 scenarios passed verification automatically.
3. **Analyze an Incident Live:**
   * Select Scenario: *Enterprise Ransomware Outbreak*.
   * Walk the examiner through the **Decision Trace Card**:
     * Point out how Critical Impact (+4) + 45 Assets (+3) + 98% Conf (+3) + Persistence (+2) + Data Exposure (+3) yields 15 points.
     * Show the threshold justification and the immediate SOP action directive.
4. **Inspect Incident History:** Filter by `CRITICAL` severity and show how the stored JSON trace is retrieved from SQLite for complete audit compliance.
5. **Inspect `rules.yaml`:** Highlight that updating a threshold does not require changing Python code.
