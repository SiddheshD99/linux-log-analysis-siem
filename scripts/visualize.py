import csv
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from collections import defaultdict
import os

# Input
CSV_FILE = "output/parsed_logs.csv"
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Load data
events = defaultdict(int)
failed_by_ip = defaultdict(int)
failed_by_user = defaultdict(int)
events_over_time = defaultdict(int)

print("[*] Loading parsed logs for visualisation...")

with open(CSV_FILE, "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        event_type = row["event_type"]
        ip = row["ip"]
        user = row["user"]
        timestamp = row["timestamp"]

        events[event_type] += 1

        if event_type in ["FAILED_LOGIN", "INVALID_USER"]:
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1

        # Extract hour for timeline
        try:
            hour = timestamp.split(" ")[2].split(":")[0]
            events_over_time[hour] += 1
        except:
            pass

# ── CHART 1: Event Type Distribution ────────────────────────
fig, ax = plt.subplots(figsize=(10, 6))
colors = ["#e74c3c", "#2ecc71", "#e67e22", "#9b59b6", "#3498db", "#1abc9c"]
bars = ax.bar(events.keys(), events.values(), color=colors[:len(events)])
ax.set_title("Log Event Type Distribution", fontsize=14, fontweight="bold")
ax.set_xlabel("Event Type")
ax.set_ylabel("Count")
ax.tick_params(axis="x", rotation=30)
for bar, val in zip(bars, events.values()):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
            str(val), ha="center", va="bottom", fontsize=9)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/chart_event_distribution.png", dpi=150)
plt.close()
print("[+] Saved: chart_event_distribution.png")

# ── CHART 2: Top IPs by Failed Attempts ─────────────────────
top_ips = dict(sorted(failed_by_ip.items(), key=lambda x: x[1], reverse=True)[:5])
fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.barh(list(top_ips.keys()), list(top_ips.values()), color="#e74c3c")
ax.set_title("Top 5 IPs by Failed/Invalid Login Attempts", fontsize=14, fontweight="bold")
ax.set_xlabel("Number of Attempts")
ax.set_ylabel("IP Address")
for bar, val in zip(bars, top_ips.values()):
    ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
            str(val), va="center", fontsize=9)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/chart_top_ips.png", dpi=150)
plt.close()
print("[+] Saved: chart_top_ips.png")

# ── CHART 3: Top Targeted Users ─────────────────────────────
top_users = dict(sorted(failed_by_user.items(), key=lambda x: x[1], reverse=True)[:8])
fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.bar(list(top_users.keys()), list(top_users.values()), color="#e67e22")
ax.set_title("Top 8 Most Targeted Usernames", fontsize=14, fontweight="bold")
ax.set_xlabel("Username")
ax.set_ylabel("Failed Attempts")
ax.tick_params(axis="x", rotation=30)
for bar, val in zip(bars, top_users.values()):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
            str(val), ha="center", va="bottom", fontsize=9)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/chart_targeted_users.png", dpi=150)
plt.close()
print("[+] Saved: chart_targeted_users.png")

# ── CHART 4: Attack Timeline by Hour ────────────────────────
hours = sorted(events_over_time.keys())
counts = [events_over_time[h] for h in hours]
fig, ax = plt.subplots(figsize=(12, 6))
ax.plot(hours, counts, color="#e74c3c", linewidth=2, marker="o", markersize=5)
ax.fill_between(hours, counts, alpha=0.2, color="#e74c3c")
ax.set_title("Security Events Timeline — Activity by Hour", fontsize=14, fontweight="bold")
ax.set_xlabel("Hour of Day")
ax.set_ylabel("Number of Events")
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/chart_timeline.png", dpi=150)
plt.close()
print("[+] Saved: chart_timeline.png")

# ── CHART 5: Severity Breakdown Pie ─────────────────────────
severity_data = {"CRITICAL": 72, "HIGH": 50, "MEDIUM": 34}
colors_pie = ["#e74c3c", "#e67e22", "#f1c40f"]
fig, ax = plt.subplots(figsize=(8, 8))
wedges, texts, autotexts = ax.pie(
    severity_data.values(),
    labels=severity_data.keys(),
    colors=colors_pie,
    autopct="%1.1f%%",
    startangle=140,
    textprops={"fontsize": 12}
)
ax.set_title("Anomaly Severity Distribution", fontsize=14, fontweight="bold")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/chart_severity_pie.png", dpi=150)
plt.close()
print("[+] Saved: chart_severity_pie.png")

print("\n[*] All charts saved to /output folder")
