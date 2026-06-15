import csv
from collections import defaultdict

# Input
CSV_FILE = "output/parsed_logs.csv"
REPORT_FILE = "output/anomaly_report.txt"

# Thresholds
BRUTE_FORCE_THRESHOLD = 10  # failed attempts from same IP
USER_ATTACK_THRESHOLD = 8   # failed attempts against same user
SUSPICIOUS_USERS = ["root", "admin", "anonymous", "hacker", "scanner", "ftpuser"]

# Storage
failed_by_ip = defaultdict(int)
failed_by_user = defaultdict(int)
sudo_usage = []
invalid_users = []
successful_logins = []

print("[*] Loading parsed logs...")

with open(CSV_FILE, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        event = row["event_type"]
        ip = row["ip"]
        user = row["user"]
        timestamp = row["timestamp"]

        if event == "FAILED_LOGIN":
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1

        elif event == "INVALID_USER":
            failed_by_ip[ip] += 1
            invalid_users.append((timestamp, user, ip))

        elif event == "SUDO_USAGE":
            sudo_usage.append((timestamp, user, row["details"]))

        elif event == "SUCCESSFUL_LOGIN":
            successful_logins.append((timestamp, user, ip))

# Build report
anomalies = []

# Check brute force by IP
for ip, count in failed_by_ip.items():
    if count >= BRUTE_FORCE_THRESHOLD:
        anomalies.append({
            "severity": "HIGH",
            "type": "BRUTE_FORCE_BY_IP",
            "detail": f"IP {ip} made {count} failed/invalid attempts — possible brute force attack"
        })

# Check targeted user attacks
for user, count in failed_by_user.items():
    if count >= USER_ATTACK_THRESHOLD:
        anomalies.append({
            "severity": "HIGH",
            "type": "USER_TARGETED_ATTACK",
            "detail": f"User '{user}' targeted {count} times — possible credential stuffing"
        })

# Check suspicious user logins
for timestamp, user, ip in successful_logins:
    if user in SUSPICIOUS_USERS:
        anomalies.append({
            "severity": "CRITICAL",
            "type": "SUSPICIOUS_USER_LOGIN",
            "detail": f"Successful login by suspicious user '{user}' from {ip} at {timestamp}"
        })

# Check sudo usage
for timestamp, user, command in sudo_usage:
    if "/bin/bash" in command or "/bin/sh" in command:
        anomalies.append({
            "severity": "HIGH",
            "type": "SUSPICIOUS_SUDO",
            "detail": f"User '{user}' ran sudo shell at {timestamp} — possible privilege escalation"
        })

# Check invalid user attempts
for timestamp, user, ip in invalid_users:
    if user in SUSPICIOUS_USERS:
        anomalies.append({
            "severity": "MEDIUM",
            "type": "INVALID_SUSPICIOUS_USER",
            "detail": f"Login attempt by known suspicious username '{user}' from {ip} at {timestamp}"
        })

# Print and save report
report_lines = []
report_lines.append("=" * 60)
report_lines.append("ANOMALY DETECTION REPORT")
report_lines.append("=" * 60)
report_lines.append(f"Total anomalies detected: {len(anomalies)}\n")

critical = [a for a in anomalies if a["severity"] == "CRITICAL"]
high = [a for a in anomalies if a["severity"] == "HIGH"]
medium = [a for a in anomalies if a["severity"] == "MEDIUM"]

report_lines.append(f"CRITICAL : {len(critical)}")
report_lines.append(f"HIGH     : {len(high)}")
report_lines.append(f"MEDIUM   : {len(medium)}")
report_lines.append("")

for severity, group in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium)]:
    if group:
        report_lines.append(f"{'=' * 60}")
        report_lines.append(f"{severity} ANOMALIES")
        report_lines.append(f"{'=' * 60}")
        for a in group:
            report_lines.append(f"[{a['type']}]")
            report_lines.append(f"  {a['detail']}")
            report_lines.append("")

report_text = "\n".join(report_lines)
print(report_text)

with open(REPORT_FILE, "w") as f:
    f.write(report_text)

print(f"[*] Anomaly report saved to: {REPORT_FILE}")
