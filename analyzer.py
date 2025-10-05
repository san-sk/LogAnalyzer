from collections import defaultdict
import re

def analyze_events(events):
    failed = defaultdict(list)
    successful = defaultdict(list)
    suspicious_ips = set()
    for event in events:
        # Extract IP address
        match = re.search(r'from ([\d.]+)', event)
        ip = match.group(1) if match else None
        if "Failed password" in event and ip:
            failed[ip].append(event)
        elif "Accepted password" in event and ip:
            successful[ip].append(event)
    # Detect brute-force (e.g., >5 failed attempts)
    for ip, attempts in failed.items():
        if len(attempts) > 5:
            suspicious_ips.add(ip)
    return {
        "failed": failed,
        "successful": successful,
        "suspicious_ips": suspicious_ips
    }

