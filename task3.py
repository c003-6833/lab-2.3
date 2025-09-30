import json
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

LOGFILE = "sample_auth_small.log"
YEAR = 2025

def parse_auth_line(line):
    """
    Parse an auth log line and return (timestamp, ip, event_type)
    """
    parts = line.split()
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"{YEAR} {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        print("Failed to parse:", line.strip(), "| ts_str:", ts_str)
        return None, None, "other"

    ip = None
    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"

    if " from " in line:
        try:
            idx = parts.index("from")
            ip = parts[idx + 1]
        except (ValueError, IndexError):
            ip = None

    return ts, ip, event_type

if __name__ == "__main__":
    # --- Task 1: Parse log ---
    per_ip_timestamps = defaultdict(list)

    with open(LOGFILE) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)
            if ts and ip and event == "failed":
                per_ip_timestamps[ip].append(ts)

    for ip in per_ip_timestamps:
        per_ip_timestamps[ip].sort()

    # --- Task 2: Detect brute-force incidents ---
    incidents = []
    window = timedelta(minutes=10)

    for ip, times in per_ip_timestamps.items():
        n = len(times)
        i = 0
        while i < n:
            j = i
            while j + 1 < n and (times[j + 1] - times[i]) <= window:
                j += 1
            count = j - i + 1
            if count >= 5:
                incidents.append({
                    "ip": ip,
                    "count": count,
                    "first": times[i].isoformat(),
                    "last": times[j].isoformat()
                })
                i = j + 1  # skip cluster
            else:
                i += 1

    # --- Task 3a: Save incidents report ---
    with open("bruteforce_incidents.txt", "w") as f:
        f.write("Detected {} brute-force incidents\n\n".format(len(incidents)))
        f.write(json.dumps(incidents, indent=2))

    print(f"Saved {len(incidents)} incidents to bruteforce_incidents.txt")

    # --- Task 3b: Summarize top IPs ---
    failed_counts = {ip: len(times) for ip, times in per_ip_timestamps.items()}
    top_attackers = Counter(failed_counts).most_common(10)

    print("\nTop attacker IPs:")
    for ip, count in top_attackers:
        print(f"{ip}: {count} failed attempts")

    with open("bruteforce_incidents.txt", "a") as f:
        f.write("\n\nTop attacker IPs:\n")
        for ip, count in top_attackers:
            f.write(f"{ip}: {count} failed attempts\n")

    # --- Task 3c: Optional bar chart ---
    if top_attackers:
        ips, counts = zip(*top_attackers)
        plt.figure(figsize=(8,4))
        plt.bar(ips, counts)
        plt.title("Top attacker IPs")
        plt.xlabel("IP")
        plt.ylabel("Failed attempts")
        plt.tight_layout()
        plt.savefig("top_attackers.png")
        plt.show()
        print("Saved bar chart as top_attackers.png")

