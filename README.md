# Windows-Service-Process-Monitoring-Agent

## How to Run the Project

### Install required libraries:

```pip install psutil wmi```

## Run the script:

```python monitor.py```

## Ensure:

### Run as Administrator

System allows WMI access

---
# Sample logs

```bash
[INFO] Monitoring started on system: WIN-USER01
[INFO] Process detected: explorer.exe (PID: 2345)
[INFO] Service running: WindowsUpdate

[ALERT] Suspicious process detected: powershell.exe -EncodedCommand
[ALERT] Unknown process execution: temp123.exe (PID: 4567)

[WARNING] High CPU usage detected: chrome.exe (85%)

[INFO] New service created: backup_service
[ALERT] Unauthorized service detected: suspicious_service

[INFO] Process terminated: notepad.exe
