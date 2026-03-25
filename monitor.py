import psutil
import wmi
import json
import time
from datetime import datetime

# ==============================
# CONFIG
# ==============================

WHITELIST = [
    "explorer.exe",
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "System"
]

SUSPICIOUS_RELATIONS = [
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("explorer.exe", "powershell.exe")
]

SUSPICIOUS_PATHS = ["Temp", "AppData", "Public"]

# ==============================
# PROCESS ENUMERATION
# ==============================

def get_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
        try:
            processes.append(proc.info)
        except:
            continue
    return processes

# ==============================
# SERVICE ENUMERATION
# ==============================

def get_services():
    c = wmi.WMI()
    services = []

    for s in c.Win32_Service():
        services.append({
            "name": s.Name,
            "path": s.PathName,
            "state": s.State
        })

    return services

# ==============================
# DETECTION ENGINE
# ==============================

def detect_parent_child(processes):
    alerts = []
    pid_map = {p['pid']: p for p in processes}

    for proc in processes:
        parent = pid_map.get(proc['ppid'])

        if parent:
            relation = (parent['name'], proc['name'])

            if relation in SUSPICIOUS_RELATIONS:
                alerts.append({
                    "type": "Parent-Child Anomaly",
                    "severity": "HIGH",
                    "details": f"{parent['name']} -> {proc['name']}",
                    "mitre": "T1059"
                })

    return alerts


def detect_unknown_processes(processes):
    alerts = []

    for proc in processes:
        try:
            if proc['name'] not in WHITELIST:
                if proc['exe'] and any(p in proc['exe'] for p in SUSPICIOUS_PATHS):
                    alerts.append({
                        "type": "Unauthorized Process",
                        "severity": "MEDIUM",
                        "details": f"{proc['name']} -> {proc['exe']}",
                        "mitre": "T1204"
                    })
        except:
            continue

    return alerts


def detect_suspicious_services(services):
    alerts = []

    for s in services:
        try:
            if s['path'] and any(p in s['path'] for p in SUSPICIOUS_PATHS):
                alerts.append({
                    "type": "Suspicious Service",
                    "severity": "HIGH",
                    "details": f"{s['name']} -> {s['path']}",
                    "mitre": "T1543"
                })
        except:
            continue

    return alerts

# ==============================
# LOGGING
# ==============================

def log_alert(alert):
    with open("logs.txt", "a") as f:
        f.write(f"[{datetime.now()}] {alert}\n")

# ==============================
# REPORT
# ==============================

def save_report(alerts):
    report_data = {
        "timestamp": str(datetime.now()),
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    with open("report.json", "w") as f:
        json.dump(report_data, f, indent=4)

# ==============================
# MAIN ENGINE
# ==============================

def run_monitor():
    print("[*] Scanning system...")

    processes = get_processes()
    services = get_services()

    alerts = []

    alerts += detect_parent_child(processes)
    alerts += detect_unknown_processes(processes)
    alerts += detect_suspicious_services(services)

    if alerts:
        print(f"[!] {len(alerts)} alerts detected\n")

        for alert in alerts:
            print(alert)
            log_alert(alert)
    else:
        print("[+] No suspicious activity detected")

    save_report(alerts)


# ==============================
# LOOP (REAL-TIME)
# ==============================

if __name__ == "__main__":
    while True:
        run_monitor()
        print("\n[*] Sleeping for 10 seconds...\n")
        time.sleep(10)
