import json
from collections import defaultdict
from datetime import datetime, timedelta

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
        print("Failed to parse:", line.strip())
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
    # --- Task 1: Parse log and build per_ip_timestamps ---
    per_ip_timestamps = defaultdict(list)

    with open(LOGFILE) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)
            if ts and ip and event == "failed":
                per_ip_timestamps[ip].append(ts)

    for ip in per_ip_timestamps:
        per_ip_timestamps[ip].sort()

    # (Optional) pretty-print per-IP timestamps
    formatted_output = {
        ip: [ts.strftime("%b %d %H:%M:%S") for ts in timestamps]
        for ip, timestamps in per_ip_timestamps.items()
    }
    print("Parsed failed attempts per IP:")
    print(json.dumps(formatted_output, indent=2))

    # --- Task 2: Detect brute-force bursts ---
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
                # Skip past this cluster to avoid duplicate overlapping reports
                i = j + 1
            else:
                i += 1

    print(f"\nDetected {len(incidents)} brute-force incidents")
    for incident in incidents[:5]:
        print(incident)



