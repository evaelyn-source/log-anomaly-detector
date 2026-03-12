import re
import json
from collections import defaultdict
from datetime import datetime

BRUTE_FORCE_THRESHOLD = 5
LOG_FILE = "sample_logs/auth.log"

def parse_log(filepath):
    failed_logins = defaultdict(list)
    successful_logins = []

    pattern_failed = re.compile(
        r'(\w+\s+\d+\s[\d:]+).*Failed password for (?:invalid user )?(\w+) from ([\d.]+)'
    )
    pattern_success = re.compile(
        r'(\w+\s+\d+\s[\d:]+).*Accepted password for (\w+) from ([\d.]+)'
    )

    with open(filepath, "r") as f:
        for line in f:
            failed_match = pattern_failed.search(line)
            success_match = pattern_success.search(line)

            if failed_match:
                timestamp, user, ip = failed_match.groups()
                failed_logins[ip].append({"user": user, "time": timestamp})
            elif success_match:
                timestamp, user, ip = success_match.groups()
                successful_logins.append({"user": user, "ip": ip, "time": timestamp})

    return failed_logins, successful_logins

def detect_brute_force(failed_logins, threshold=BRUTE_FORCE_THRESHOLD):
    alerts = []
    for ip, attempts in failed_logins.items():
        if len(attempts) >= threshold:
            alerts.append({
                "type": "BRUTE_FORCE",
                "ip": ip,
                "attempts": len(attempts),
                "targeted_users": list({a["user"] for a in attempts}),
                "severity": "HIGH"
            })
    return alerts

def generate_report(alerts, successful_logins):
    report = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_alerts": len(alerts),
            "successful_logins": len(successful_logins)
        },
        "alerts": alerts,
        "successful_logins": successful_logins
    }

    with open("reports/report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "="*50)
    print("  LOG ANOMALY DETECTOR - REPORT")
    print("="*50)
    print(f"  Alerts Found     : {len(alerts)}")
    print(f"  Successful Logins: {len(successful_logins)}")
    print("\n  ALERTS:")
    for alert in alerts:
        print(f"\n  !! [{alert['severity']}] {alert['type']}")
        print(f"     IP Address : {alert['ip']}")
        print(f"     Attempts   : {alert['attempts']}")
        print(f"     Targeted   : {', '.join(alert['targeted_users'])}")
    print(f"\n  Full report saved to reports/report.json")
    print("="*50 + "\n")

if __name__ == "__main__":
    print("Running Log Anomaly Detector...")
    failed, successful = parse_log(LOG_FILE)
    alerts = detect_brute_force(failed)
    generate_report(alerts, successful)