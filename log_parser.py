import re

def parse_log(filepath):
    events = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                # Example: parse failed and successful logins
                if "Failed password" in line or "Accepted password" in line:
                    events.append(line.strip())
    except Exception as e:
        print(f"Error reading log file: {e}")
    return events

