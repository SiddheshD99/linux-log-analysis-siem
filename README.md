# Linux Log Analysis, Automation and SIEM Visualisation

## Overview
This project demonstrates the process of collecting, parsing, and analysing 
Linux system logs using Python automation scripts, with findings visualised 
in a SIEM dashboard. The goal is to simulate a real-world log monitoring 
workflow — identifying suspicious activity, automating detection, and 
presenting findings in a format suitable for security operations teams.

## Objectives
- Collect and analyse Linux system logs including auth.log and syslog
- Write Python scripts to automate log parsing and anomaly detection
- Identify indicators of suspicious activity such as failed logins, 
  privilege escalation attempts, and unusual process execution
- Ingest parsed logs into a SIEM and build detection dashboards
- Document findings in a structured security report

## Tools & Technologies
- **OS:** Kali Linux
- **Language:** Python 3
- **Logs Analysed:** auth.log, syslog, kern.log
- **SIEM:** Splunk Free / Microsoft Sentinel
- **Libraries:** re, pandas, matplotlib, datetime
- **Version Control:** Git

## Project Structure

## What I Built
A complete log analysis pipeline consisting of three Python scripts:
- A log generator that creates realistic Linux SSH authentication logs
- A log parser that extracts and categorises security events using regex
- An anomaly detector that flags brute force attacks, credential stuffing, 
  suspicious logins, and privilege escalation attempts
- A visualisation script that generates security charts from the parsed data

## Key Findings
Analysis of 500 simulated log entries revealed 156 anomalies — 72 critical, 
50 high, and 34 medium severity. Key findings include 5 IPs conducting brute 
force attacks, 72 successful logins by suspicious default usernames, and 
35 instances of sudo shell spawning indicating privilege escalation. 
Full findings documented in /docs/findings.md

## How to Run
```bash
python3 scripts/log_generator.py
python3 scripts/log_parser.py
python3 scripts/anomaly_detector.py
python3 scripts/visualise.py
```

## SIEM Integration
This project includes a complete guide for ingesting parsed logs into 
Splunk or Microsoft Sentinel for dashboard visualisation and automated 
alerting. See /docs/siem-setup.md for full setup instructions and KQL queries.

## Mapped Frameworks
- NIST CSF 2.0 — Detect (DE.CM) Security Continuous Monitoring
- MITRE ATT&CK — T1078 Valid Accounts, T1110 Brute Force

## Author
**Siddhesh Dahiphale**  
[LinkedIn](https://www.linkedin.com/in/siddhesh-dahiphale) | [GitHub](https://github.com/SiddheshD99)
