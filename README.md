# SOC Brute Force Detector

A Windows-based SOC detection project that identifies potential brute-force authentication activity using Windows Security Event ID 4625.

## Project Overview

This project simulates a small SOC detection workflow:

**Collect → Parse → Correlate → Detect → Alert → Investigate → Document**

The detector monitors Windows Security logs for repeated failed logon events and identifies bursts of authentication failures from the same source IP against the same target account.

## Detection Objective

Detect potential brute-force authentication activity when:

> **5 or more failed logon attempts occur within 5 minutes from the same source IP against the same target account.**

Windows Security **Event ID 4625** represents a failed logon attempt.

## Detection Logic

The detector performs the following steps:

1. Collect Event ID 4625 from the Windows Security log.
2. Parse the event XML.
3. Extract relevant authentication fields.
4. Maintain a rolling time window.
5. Correlate events using:

   * Source IP
   * Target account
6. Count failures within the configured window.
7. Generate an alert when the threshold is reached.
8. Assign a severity based on the number of failures.
9. Record investigation evidence.

### Detection Rule

```text
IF
    Event ID = 4625
AND
    Same Source IP
AND
    Same Target Account
AND
    >= 5 failures
    within 5 minutes

THEN
    Generate potential brute-force alert
```

## Severity Logic

| Failed Logons | Severity |
| ------------: | -------- |
|           5–9 | Medium   |
|         10–19 | High     |
|           20+ | Critical |

These thresholds are configurable and are intended for this lab environment.

## Technologies

* Windows Security Event Log
* PowerShell
* Windows Event ID 4625
* WMI event monitoring
* XML event parsing
* Rolling time-window detection
* Source IP + account correlation

## Project Components

```text
SOC-BruteForce/
│
├── BruteForceDetector.ps1
├── TestBruteForce.ps1
├── Evidence/
└── README.md
```

## Detection Modes

### Historical Detection

The detector can analyze previously recorded Event ID 4625 events within a configurable lookback period.

Example:

```text
Lookback: 168 hours
Detection window: 5 minutes
Threshold: 5 failures
```

### Real-Time Detection

The live monitor watches the Windows Security log for newly created Event ID 4625 events.

When a new event appears, it:

1. Retrieves the exact Windows event.
2. Parses the event.
3. Adds it to the rolling window.
4. Correlates it with previous failures.
5. Calculates the current failure count.
6. Generates an alert if the threshold is reached.

## Testing

The project was tested using controlled simulated authentication events.

### Negative Test

A small number of failures below the threshold did not generate an alert.

Expected behavior:

```text
4 failures
within 5 minutes
        ↓
No alert
```

### Positive Test

A controlled burst reaching the threshold generated a potential brute-force detection.

Expected behavior:

```text
5 failures
within 5 minutes
        ↓
Potential Brute Force Alert
        ↓
Medium severity
```

### Severity Testing

The detection logic was also tested with higher event counts:

```text
5 failures  → Medium
10 failures → High
20 failures → Critical
```

## Real Windows Events

The detector was also tested against actual Windows Security Event ID 4625 events generated on the lab machine.

The observed events included local authentication activity such as:

```text
Event ID   : 4625
Source IP  : 127.0.0.1
Logon Type : 2
```

These events were used to validate real event collection and parsing.

A single Event ID 4625 does **not** prove that a brute-force attack occurred.

The detector therefore requires repeated failures within a defined time window and correlates the source and target context before generating an alert.

## Analyst Investigation Workflow

When an alert is generated, an analyst should investigate:

1. **Source**

   * Is the source IP expected?
   * Does it belong to the organization or lab system?

2. **Target**

   * Which account was targeted?
   * Is the account legitimate?

3. **Frequency**

   * How many failures occurred?
   * How quickly did they occur?

4. **Logon Context**

   * What Logon Type was used?
   * What authentication package was involved?

5. **Related Events**

   * Review surrounding Security events.
   * Look for successful logons following the failures.

6. **Assessment**

   * Determine whether the activity is expected or suspicious.

7. **Documentation**

   * Preserve the relevant events and investigation findings.

## Evidence

Detection evidence is stored in:

```text
C:\SOC-BruteForce\Evidence
```

Evidence reports contain information such as:

* Detection time
* Source IP
* Target account
* Number of failures
* Detection window
* Event IDs
* Record IDs
* Logon Type
* Status
* SubStatus
* Process
* Observed events
* Analyst investigation guidance
* Assessment
* Recommendation

## False Positives

Repeated 4625 events do not automatically mean malicious activity.

Possible legitimate causes include:

* Incorrect passwords
* User authentication mistakes
* Local applications attempting authentication
* Administrative activity
* Misconfigured services or applications

For this reason, the detector is intentionally described as detecting **potential** brute-force activity rather than proving an attack.

## Limitations

This project is a local SOC lab and has several limitations:

* It currently focuses on Windows Event ID 4625.
* It does not replace a production SIEM.
* IP and account fields may be unavailable or represented differently depending on the authentication context.
* Event ID 4625 alone cannot establish attacker intent.
* Additional telemetry is required for stronger incident correlation.

## Future Improvements

Possible future extensions include:

* Sysmon correlation
* Successful-logon correlation
* Event ID 4648 correlation
* Event ID 4672 correlation
* Sigma detection rule
* SIEM ingestion
* MITRE ATT&CK mapping
* Automated investigation enrichment
* Dashboard visualization
* Python-based automation

## Project Goal

The goal of this project is not simply to collect Windows logs.

It demonstrates a basic SOC workflow:

```text
Security Event
      ↓
Detection Logic
      ↓
Correlation
      ↓
Alert
      ↓
Investigation
      ↓
Evidence
      ↓
Analyst Assessment
```

## MITRE ATT&CK Mapping

This detection is mapped to the MITRE ATT&CK Enterprise technique:

### T1110 — Brute Force

**Tactic:** Credential Access

**Technique:** T1110 — Brute Force

The detector is designed to identify repeated failed authentication attempts that may be consistent with brute-force activity.

### Why This Mapping Applies

The detection rule looks for:

```text
Event ID 4625
      ↓
Repeated failed logons
      ↓
Same Source IP
      ↓
Same Target Account
      ↓
5+ failures within 5 minutes
      ↓
Potential Brute Force Detection
```

The correlation logic is intended to identify a pattern of repeated authentication failures rather than treating a single failed logon as malicious.

### Detection-to-ATT&CK Relationship

| Detection Component | Project Implementation       |
| ------------------- | ---------------------------- |
| ATT&CK Technique    | T1110 — Brute Force          |
| ATT&CK Tactic       | Credential Access            |
| Windows Event       | Event ID 4625                |
| Detection Condition | 5+ failures within 5 minutes |
| Correlation         | Source IP + Target Account   |
| Output              | Potential brute-force alert  |
| Evidence            | Detection report             |

### Important Limitation

The presence of Event ID 4625 does **not** prove that T1110 activity occurred.

A failed authentication can have legitimate causes, such as an incorrect password or an application attempting authentication with invalid credentials.

Therefore, this project treats the ATT&CK mapping as a **detection hypothesis**:

> Repeated authentication failures matching the detection rule may indicate activity consistent with T1110 — Brute Force.

Additional investigation and telemetry are required before determining whether the activity is malicious.

### ATT&CK Reference

MITRE ATT&CK Enterprise Framework:

**T1110 — Brute Force**

https://attack.mitre.org/techniques/T1110/




This project was built as a hands-on Blue Team / SOC learning project.
