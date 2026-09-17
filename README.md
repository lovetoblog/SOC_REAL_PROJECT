# SOC_REAL_PROJECT
BRUTE FORCE DETECTION 
# SOC Brute Force Detector

A PowerShell-based Blue Team detection project that identifies **potential brute-force authentication activity** using Windows Security Event ID 4625.

The project demonstrates a small SOC detection workflow:

**Collect → Parse → Correlate → Detect → Alert → Investigate → Document**

---

## 📌 Project Overview

Authentication failures are common in Windows environments. A single failed login does not necessarily indicate malicious activity.

This project detects **repeated Event ID 4625 failures** by correlating:

* Source IP
* Target account
* Failure frequency
* Time window

### Detection Rule

```text
IF

Event ID = 4625
AND
Same Source IP
AND
Same Target Account
AND
5 or more failures occur within 5 minutes

THEN

Generate a Potential Brute Force Alert
```

The detector can analyze historical Windows events and monitor newly generated Event ID 4625 events in real time.

---

## 🎯 Objectives

The main objectives of this project are to:

* Understand Windows Security Event ID 4625
* Parse Windows Event XML
* Build a time-based detection rule
* Correlate authentication failures
* Detect repeated failed logons
* Assign alert severity
* Monitor events in real time
* Generate investigation evidence
* Map the detection to MITRE ATT&CK
* Practice SOC L1 detection and investigation workflows

---

## 🛠️ Technologies Used

* **PowerShell**
* **Windows Security Event Log**
* **Windows Event ID 4625**
* **WMI Event Monitoring**
* **XML Event Parsing**
* **Rolling Time-Window Detection**
* **Source IP + Target Account Correlation**
* **MITRE ATT&CK**

---

## 🔎 Windows Event ID 4625

**Event ID 4625** is generated when a logon attempt fails.

The detector extracts useful fields from the event XML, including:

```text
TimeCreated
EventID
RecordId
TargetUserName
LogonType
Status
SubStatus
IpAddress
ProcessName
```

These fields provide context for investigating authentication failures.

---

# 🧠 Detection Logic

The detector uses a **rolling 5-minute window**.

For every new Event ID 4625:

1. Retrieve the exact Windows event.
2. Parse the event XML.
3. Extract authentication fields.
4. Add the event to the recent-event collection.
5. Remove events outside the 5-minute window.
6. Correlate events using Source IP + Target Account.
7. Count matching failures.
8. Compare the count against the threshold.
9. Generate an alert if the threshold is reached.
10. Create investigation evidence.

### Detection Flow

```text
Windows Security Log
        │
        ▼
Event ID 4625
        │
        ▼
Parse Event XML
        │
        ▼
Extract Source IP + Account
        │
        ▼
5-Minute Rolling Window
        │
        ▼
Correlate Matching Events
        │
        ▼
Count Failed Logons
        │
        ├── < 5 ──► No Alert
        │
        └── ≥ 5 ──► Potential Brute Force Alert
                         │
                         ▼
                    Severity
                         │
                         ▼
                  Evidence Report
```

---

# 🚨 Severity Classification

The detector uses the following lab thresholds:

| Failed Logons | Severity |
| ------------: | -------- |
|           5–9 | Medium   |
|         10–19 | High     |
|           20+ | Critical |

These values are configurable and are intended for this lab environment.

---

# 🧪 Testing

The detector was tested using controlled simulated events as well as real Windows Security Event ID 4625 events generated on the lab machine.

## Negative Test

The detector was tested with fewer failures than the configured threshold.

```text
4 failures
within 5 minutes
        ↓
No Alert
```

This confirms that the detector does not alert simply because Event ID 4625 exists.

---

## Positive Test

The detector was tested with a controlled burst reaching the threshold.

```text
5 failures
within 5 minutes
        ↓
Potential Brute Force Alert
        ↓
Medium Severity
```

---

## Severity Tests

The severity logic was tested with different event counts:

```text
5 failures  → Medium
10 failures → High
20 failures → Critical
```

---

# 🖥️ Real Windows Event Testing

The detector was also tested against actual Windows Security Event ID 4625 events generated on the lab machine.

Example observed context:

```text
Event ID   : 4625
Source IP  : 127.0.0.1
Logon Type : 2
```

The real events demonstrated that the detector can collect and parse live Windows authentication failures.

However:

> **A single Event ID 4625 does not prove that a brute-force attack occurred.**

For example, authentication failures can result from:

* Incorrect passwords
* User mistakes
* Local applications
* Misconfigured authentication
* Administrative activity

Therefore, this project detects **potential** brute-force activity based on repeated failures and correlation.

---

# ⚡ Real-Time Monitoring

The live monitor watches the Windows Security log for newly created Event ID 4625 events.

When a new event is detected, the monitor:

```text
New Event 4625
      ↓
Retrieve exact Record ID
      ↓
Parse event
      ↓
Update rolling window
      ↓
Correlate Source IP + Account
      ↓
Calculate failure count
      ↓
Check threshold
```

Example live output:

```text
NEW SECURITY EVENT 4625

Time       : [event time]
Record ID  : [event record ID]
Source IP  : 127.0.0.1
Account    : -
Logon Type : 2
Failures   : 1 / 5
Window     : 5 minutes
```

When the configured threshold is reached, the detector can generate a potential brute-force alert and create an evidence report.

---

# 📄 Evidence Collection

Detection evidence is stored under:

```text
C:\SOC-BruteForce\Evidence
```

Reports can contain:

* Detection timestamp
* Source IP
* Target account
* Number of failed logons
* Detection window
* Event ID
* Record ID
* Logon Type
* Status
* SubStatus
* Process
* Observed events
* Analyst investigation steps
* Assessment
* Recommendation

Example evidence structure:

```text
Evidence/
│
├── BruteForce_Alert_*.txt
├── BruteForce_NoAlert_*.txt
└── LiveBruteForce_Alert_*.txt
```

---

# 🔬 SOC Analyst Investigation Workflow

A detection should not immediately be treated as a confirmed security incident.

After an alert, an analyst should investigate:

### 1. Source

Determine whether the source IP is expected.

```text
Is the source authorized?
Is it a known workstation/server?
Is the activity coming from an expected network?
```

### 2. Target Account

Identify the account being targeted.

```text
Is the account legitimate?
Is it a privileged account?
Is the account expected on this system?
```

### 3. Authentication Pattern

Review:

* Number of failures
* Time between failures
* Logon Type
* Authentication package
* Status/SubStatus

### 4. Related Events

Review surrounding Windows Security events.

Particularly investigate whether successful authentication occurs after repeated failures.

### 5. Determine Context

Ask whether the activity could be explained by:

* User error
* Application behavior
* Administrative activity
* Configuration problems
* Unauthorized authentication attempts

### 6. Document Findings

Record:

```text
What happened?
When did it happen?
Which account was involved?
Where did it originate?
How many failures occurred?
Were there successful logons?
Is the activity expected?
What should happen next?
```

---

# 🗺️ MITRE ATT&CK Mapping

## T1110 — Brute Force

**Tactic:** Credential Access

**Technique:** T1110 — Brute Force

This project is designed to detect repeated authentication failures that may be consistent with brute-force activity.

### Detection Relationship

| ATT&CK / Detection Element | Implementation              |
| -------------------------- | --------------------------- |
| Technique                  | T1110 — Brute Force         |
| Tactic                     | Credential Access           |
| Windows Event              | Event ID 4625               |
| Detection Window           | 5 minutes                   |
| Threshold                  | 5 failures                  |
| Correlation                | Source IP + Target Account  |
| Detection Output           | Potential brute-force alert |
| Evidence                   | Investigation report        |

### Mapping Logic

```text
Repeated Authentication Failures
             │
             ▼
      Event ID 4625
             │
             ▼
 Same Source + Same Account
             │
             ▼
 5+ Failures / 5 Minutes
             │
             ▼
 Potential T1110 Activity
```

### Important Limitation

The ATT&CK mapping does **not** mean that every Event ID 4625 represents T1110.

The mapping represents a detection hypothesis based on the observed authentication pattern.

Additional telemetry and investigation are required to determine whether the activity is actually malicious.

---

# ⚠️ False Positives

Potential false positives include:

* Users entering an incorrect password
* Applications attempting authentication with invalid credentials
* Misconfigured services
* Administrative activity
* Local authentication failures

This is why the detector uses:

**Time + Source + Account + Failure Count**

rather than treating every 4625 event as malicious.

---

# ⚠️ Limitations

This project is a local SOC lab and is not intended to replace a production SIEM.

Current limitations include:

* Focuses primarily on Event ID 4625
* Authentication fields vary depending on the logon context
* Source IP may be local or unavailable
* Target account information may sometimes be unavailable
* Event ID 4625 alone cannot prove malicious intent
* Additional telemetry is required for stronger correlation
* Thresholds require tuning for different environments

---

# 📁 Project Structure

```text
SOC-BruteForce/
│
├── BruteForceDetector.ps1
├── TestBruteForce.ps1
├── LiveBruteForceMonitor.ps1
├── README.md
│
├── Evidence/
│
└── Screenshots/
```

### File Description

| File                        | Purpose                                   |
| --------------------------- | ----------------------------------------- |
| `BruteForceDetector.ps1`    | Historical brute-force detection          |
| `TestBruteForce.ps1`        | Controlled detection and severity testing |
| `LiveBruteForceMonitor.ps1` | Real-time Event ID 4625 monitoring        |
| `README.md`                 | Project documentation                     |
| `Evidence/`                 | Detection and investigation reports       |
| `Screenshots/`              | Project evidence for documentation        |

---

# 🚀 Future Improvements

Possible extensions for this project include:

* Sysmon correlation
* Successful-logon correlation
* Event ID 4648 correlation
* Event ID 4672 correlation
* Sigma detection rule
* SIEM integration
* KQL implementation
* MITRE ATT&CK enrichment
* Automated investigation
* Python-based automation
* Detection dashboard

---

# 🎓 What I Learned

Through this project, I practiced:

* Windows Event Log analysis
* Event XML parsing
* PowerShell scripting
* Detection engineering
* Time-based correlation
* Authentication investigation
* Alert severity classification
* False-positive analysis
* Evidence collection
* MITRE ATT&CK mapping
* Basic SOC analyst workflow

The key lesson was that **detecting an event is not the same as proving an attack**.

A useful SOC detection needs context, correlation, investigation, and evidence.

---

# 🔄 SOC Detection Workflow

This project follows a simplified SOC workflow:

```text
COLLECT
   ↓
Windows Security Event 4625
   ↓
PARSE
   ↓
Extract authentication fields
   ↓
CORRELATE
   ↓
Source IP + Target Account
   ↓
DETECT
   ↓
5+ failures within 5 minutes
   ↓
ALERT
   ↓
Severity classification
   ↓
INVESTIGATE
   ↓
Review authentication context
   ↓
DOCUMENT
   ↓
Evidence report
```

---

# 📌 Project Status

**Status: Functional SOC Detection Lab**

Completed:

* [x] Event ID 4625 collection
* [x] XML parsing
* [x] Historical detection
* [x] Rolling time-window detection
* [x] Source IP + account correlation
* [x] Severity classification
* [x] Controlled testing
* [x] Real Windows event testing
* [x] Real-time monitoring
* [x] Evidence generation
* [x] MITRE ATT&CK mapping
* [x] SOC investigation workflow

---



Built as a hands-on **Blue Team / SOC learning project** to practice Windows authentication monitoring, detection engineering, and security investigation.
