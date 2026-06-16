# Security Findings Report — Linux Log Analysis

## Overview
This document presents the findings from automated analysis of a simulated 
Linux authentication log containing 500 events generated over a 24-hour period. 
Three Python scripts were used to generate, parse, and detect anomalies across 
the log data, simulating a real-world SOC log monitoring workflow.

---

## Environment
- **OS:** Kali Linux
- **Log Type:** SSH Authentication Log (auth.log format)
- **Log Period:** 24 hours (Jun 01 2026)
- **Total Events:** 500
- **Analysis Tools:** Python 3, custom log parser and anomaly detector

---

## Summary of Events

| Event Type | Count | % of Total |
|---|---|---|
| Failed Login | 200 | 40% |
| Successful Login | 111 | 22.2% |
| Invalid User | 58 | 11.6% |
| Session Opened | 56 | 11.2% |
| Session Closed | 40 | 8% |
| Sudo Usage | 35 | 7% |

**Key Observation:** 40% of all events were failed login attempts — a significantly 
elevated rate indicating active brute force or credential stuffing activity against 
this system during the monitored period.

---

## Anomalies Detected

### Total Anomalies: 156

| Severity | Count | % of Anomalies |
|---|---|---|
| Critical | 72 | 46.2% |
| High | 50 | 32.1% |
| Medium | 34 | 21.8% |

---

## Critical Findings

### 1. Suspicious User Logins (72 incidents)
Multiple successful authentications were recorded for known suspicious 
usernames including `root`, `admin`, `anonymous`, `hacker`, `scanner`, 
and `ftpuser` from external IP addresses.

**Risk:** Successful authentication by these usernames from external IPs 
indicates either compromised credentials or active exploitation of default 
accounts that should not exist on a hardened system.

**Affected IPs:**
- 45.33.32.156 — 13 suspicious logins
- 172.16.0.55 — 12 suspicious logins
- 10.0.0.23 — 12 suspicious logins
- 192.168.1.105 — 11 suspicious logins
- 198.51.100.77 — 11 suspicious logins

**Recommended Action:**
- Disable default accounts immediately
- Force password reset on all affected accounts
- Block all identified external IPs at the firewall
- Enable MFA for all SSH access

---

## High Severity Findings

### 2. Brute Force Attacks by IP (5 incidents)
All 5 monitored external IPs exceeded the brute force threshold of 
10 failed attempts within the 24-hour period.

| IP Address | Failed Attempts |
|---|---|
| 172.16.0.55 | 59 |
| 192.168.1.105 | 57 |
| 45.33.32.156 | 48 |
| 10.0.0.23 | 47 |
| 198.51.100.77 | 47 |

**Risk:** Coordinated brute force activity from multiple IPs suggests 
a distributed attack — potentially a botnet conducting credential stuffing 
against this system.

**Recommended Action:**
- Implement fail2ban to automatically block IPs after failed attempts
- Enable SSH rate limiting
- Consider moving SSH to a non-standard port
- Implement geoblocking for unexpected source countries

### 3. Credential Stuffing Against User Accounts (10 users targeted)
All monitored usernames were targeted more than 8 times each during 
the 24-hour period.

| Username | Attempts |
|---|---|
| ftpuser | 26 |
| hacker | 25 |
| anonymous | 25 |
| scanner | 22 |
| ubuntu | 21 |

**Recommended Action:**
- Remove non-essential user accounts
- Enforce strong password policies
- Implement account lockout after failed attempts

### 4. Suspicious Sudo Usage (35 incidents)
35 sudo commands were executed running `/bin/bash` or `/bin/sh` — 
indicating shell spawning via sudo which is a common privilege 
escalation technique.

**Recommended Action:**
- Audit sudoers file and restrict sudo permissions
- Log all sudo activity to a remote syslog server
- Alert on any sudo shell spawning in real time

---

## Medium Severity Findings

### 5. Invalid Suspicious Username Attempts (34 incidents)
34 login attempts used known malicious or default usernames that 
should not exist on this system — indicating automated scanning 
or targeted reconnaissance.

**Recommended Action:**
- Configure SSH to reject connections for non-existent users immediately
- Review and harden SSH configuration (sshd_config)

---

## MITRE ATT&CK Mapping

| Finding | MITRE Technique | ID |
|---|---|---|
| Brute Force by IP | Brute Force | T1110 |
| Credential Stuffing | Credential Stuffing | T1110.004 |
| Suspicious User Login | Valid Accounts | T1078 |
| Sudo Shell Spawning | Abuse Elevation Control | T1548 |
| Reconnaissance via Invalid Users | Network Service Scanning | T1046 |

---

## Recommendations Summary

| Priority | Action | Timeframe |
|---|---|---|
| Critical | Block all 5 attacker IPs at firewall | Immediate |
| Critical | Disable default and suspicious accounts | Immediate |
| High | Deploy fail2ban for automatic IP blocking | 24 hours |
| High | Restrict sudo permissions and audit sudoers | 48 hours |
| High | Enable SSH rate limiting | 48 hours |
| Medium | Move SSH to non-standard port | 1 week |
| Medium | Implement MFA for all SSH access | 1 week |
| Medium | Configure remote syslog for audit trail | 1 week |

---

*Last Updated: June 2026*
