import json
from collections import defaultdict
from datetime import datetime

LOGFILE = "sample_auth_small.log"

def parse_auth_line(line):
    """
    Parse an auth log line and return (timestamp, ip, event_type)
    """
    parts = line.split()
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        print("Failed to parse:", line.strip())  # 🔧 Print offending line
        ts = None

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
    per_ip_timestamps = defaultdict(list)

    with open(LOGFILE) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)
            if ts and ip and event == "failed":
                per_ip_timestamps[ip].append(ts)

 
    for ip in per_ip_timestamps:
        per_ip_timestamps[ip].sort()

    formatted_output = {}
    for ip, timestamps in per_ip_timestamps.items():
        formatted_output[ip] = [ts.strftime("%b %d %H:%M:%S") for ts in timestamps]

    print(json.dumps(formatted_output, indent=2))
