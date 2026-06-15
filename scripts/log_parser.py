import re
import csv
from datetime import datetime
from collections import defaultdict

# Input/output paths
LOG_FILE = "logs/sample_auth.log"
OUTPUT_CSV = "output/parsed_logs.csv"

# Regex patterns
PATTERNS = {
    "failed_login": r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for (\S+) from (\S+) port (\d+)",
    "successful_login": r"(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted password for (\S+) from (\S+) port (\d+)",
    "invalid_user": r"(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\S+) from (\S+) port (\d+)",
    "sudo_usage": r"(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*(\S+)\s+:.*COMMAND=(.*)",
    "session_opened": r"(\w+\s+\d+\s+\d+:\d+:\d+).*session opened for user (\S+)",
    "session_closed": r"(\w+\s+\d+\s+\d+:\d+:\d+).*session closed for user (\S+)",
}

# Storage
parsed_events = []
stats = defaultdict(int)
failed_by_ip = defaultdict(int)
failed_by_user = defaultdict(int)

print("[*] Starting log analysis...")
print(f"[*] Reading: {LOG_FILE}\n")

with open(LOG_FILE, "r") as f:
    for line in f:
        line = line.strip()

        # Failed login
        match = re.search(PATTERNS["failed_login"], line)
        if match:
            timestamp, user, ip, port = match.groups()
            parsed_events.append({
                "timestamp": timestamp,
                "event_type": "FAILED_LOGIN",
                "user": user,
                "ip": ip,
                "port": port,
                "details": ""
            })
            stats["failed_login"] += 1
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1
            continue

        # Successful login
        match = re.search(PATTERNS["successful_login"], line)
        if match:
            timestamp, user, ip, port = match.groups()
            parsed_events.append({
                "timestamp": timestamp,
                "event_type": "SUCCESSFUL_LOGIN",
                "user": user,
                "ip": ip,
                "port": port,
                "details": ""
            })
            stats["successful_login"] += 1
            continue

        # Invalid user
        match = re.search(PATTERNS["invalid_user"], line)
        if match:
            timestamp, user, ip, port = match.groups()
            parsed_events.append({
                "timestamp": timestamp,
                "event_type": "INVALID_USER",
                "user": user,
                "ip": ip,
                "port": port,
                "details": ""
            })
            stats["invalid_user"] += 1
            failed_by_ip[ip] += 1
            continue

        # Sudo usage
        match = re.search(PATTERNS["sudo_usage"], line)
        if match:
            timestamp, user, command = match.groups()
            parsed_events.append({
                "timestamp": timestamp,
                "event_type": "SUDO_USAGE",
                "user": user,
                "ip": "localhost",
                "port": "N/A",
                "details": command.strip()
            })
            stats["sudo_usage"] += 1
            continue

        # Session opened
        match = re.search(PATTERNS["session_opened"], line)
        if match:
            timestamp, user = match.groups()
            parsed_events.append({
                "timestamp": timestamp,
                "event_type": "SESSION_OPENED",
                "user": user,
                "ip": "N/A",
                "port": "N/A",
                "details": ""
            })
            stats["session_opened"] += 1
            continue

        # Session closed
        match = re.search(PATTERNS["session_closed"], line)
        if match:
            timestamp, user = match.groups()
            parsed_events.append({
                "timestamp": timestamp,
                "event_type": "SESSION_CLOSED",
                "user": user,
                "ip": "N/A",
                "port": "N/A",
                "details": ""
            })
            stats["session_closed"] += 1
            continue

# Write to CSV
import os
os.makedirs("output", exist_ok=True)
with open(OUTPUT_CSV, "w", newline="") as csvfile:
    fieldnames = ["timestamp", "event_type", "user", "ip", "port", "details"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(parsed_events)

# Print summary
print("=" * 50)
print("LOG ANALYSIS SUMMARY")
print("=" * 50)
print(f"Total events parsed:     {len(parsed_events)}")
print(f"Failed logins:           {stats['failed_login']}")
print(f"Successful logins:       {stats['successful_login']}")
print(f"Invalid user attempts:   {stats['invalid_user']}")
print(f"Sudo usage:              {stats['sudo_usage']}")
print(f"Sessions opened:         {stats['session_opened']}")
print(f"Sessions closed:         {stats['session_closed']}")
print()
print("TOP 5 IPs BY FAILED ATTEMPTS:")
for ip, count in sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"  {ip:<20} {count} attempts")
print()
print("TOP 5 TARGETED USERS:")
for user, count in sorted(failed_by_user.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"  {user:<20} {count} attempts")
print()
print(f"[*] Parsed log saved to: {OUTPUT_CSV}")
