import json
from collections import defaultdict, Counter
import matplotlib.pyplot as plt

log_file = "sample_auth_small.log"
incident_file = "bruteforce_incidents.txt"
report_file = "bruteforce_report.txt"

# Step 1: Parse log and aggregate failed attempts by IP
failed_attempts = defaultdict(list)  # IP -> list of timestamps (string or datetime)

with open(log_file) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        # Example line parsing: adjust if your log format differs
        # Let's assume a simple format like:
        # TIMESTAMP IP MESSAGE
        # And failed attempts include "Failed password" or similar text
        
        # For example: "2025-09-29 15:20:33 203.0.113.45 Failed password for user"
        if "Failed password" in line:
            parts = line.split()
            # naive parsing example:
            # timestamp = parts[0] + " " + parts[1]
            # ip = parts[2]
            # You will need to adjust this based on actual log format

            timestamp = parts[0] + " " + parts[1]
            ip = parts[2]
            failed_attempts[ip].append(timestamp)

# Step 2: Create incidents (here, incidents = total failed attempts per IP)
ip_fail_counts = {ip: len(times) for ip, times in failed_attempts.items()}

# Step 3: Save incidents (failed attempts per IP) to a pretty JSON file
with open(incident_file, 'w') as f:
    json.dump(failed_attempts, f, indent=4)

# Step 4: Generate summary report of top offending IPs
top_offenders = Counter(ip_fail_counts).most_common(10)

with open(report_file, 'w') as f:
    f.write("Top offending IPs by failed login attempts:\n")
    for ip, count in top_offenders:
        f.write(f"{ip}: {count} failed attempts\n")

# Optional Step 5: Plot bar chart of top 10 attacker IPs
ips = [ip for ip, _ in top_offenders]
counts = [count for _, count in top_offenders]

plt.figure(figsize=(8,4))
plt.bar(ips, counts)
plt.title("Top attacker IPs")
plt.xlabel("IP")
plt.ylabel("Failed attempts")
plt.tight_layout()
plt.savefig("top_attackers.png")
plt.show()
