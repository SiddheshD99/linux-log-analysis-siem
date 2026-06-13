import random
import datetime
import os

# Output path
log_file = "logs/sample_auth.log"

# Sample data
users = ["root", "admin", "siddhesh", "ubuntu", "test", "guest"]
invalid_users = ["hacker", "scanner", "anonymous", "ftpuser"]
ips = ["192.168.1.105", "10.0.0.23", "172.16.0.55", "45.33.32.156", "198.51.100.77"]

lines = []
base_time = datetime.datetime(2026, 6, 1, 0, 0, 0)

for i in range(500):
    timestamp = base_time + datetime.timedelta(seconds=random.randint(0, 86400))
    ts = timestamp.strftime("%b %d %H:%M:%S")
    ip = random.choice(ips)
    user = random.choice(users + invalid_users)
    event = random.randint(1, 10)

    if event <= 4:
        # Failed login
        line = f"{ts} kali sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
    elif event <= 6:
        # Successful login
        line = f"{ts} kali sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
    elif event <= 7:
        # Invalid user
        line = f"{ts} kali sshd[{random.randint(1000,9999)}]: Invalid user {user} from {ip} port {random.randint(1024,65535)}"
    elif event <= 8:
        # Sudo usage
        line = f"{ts} kali sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"
    elif event <= 9:
        # Session opened
        line = f"{ts} kali sshd[{random.randint(1000,9999)}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)"
    else:
        # Session closed
        line = f"{ts} kali sshd[{random.randint(1000,9999)}]: pam_unix(sshd:session): session closed for user {user}"

    lines.append(line)

# Sort by timestamp
lines.sort()

# Write to file
os.makedirs("logs", exist_ok=True)
with open(log_file, "w") as f:
    f.write("\n".join(lines))

print(f"Generated {len(lines)} log entries -> {log_file}")
