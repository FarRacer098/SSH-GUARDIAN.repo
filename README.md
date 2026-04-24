# 🛡️ SSH Guardian

**SSH Guardian** is a real-time security monitoring tool designed to detect and prevent brute-force attacks on SSH servers. It continuously analyzes system logs, tracks failed login attempts, blocks malicious IPs, and generates incident reports.

---

## 🚀 Features

- 🔍 Real-time monitoring of SSH logs using `journalctl`
- 🚫 Automatic IP blocking after threshold breach
- 📊 Tracks failed login attempts within a defined time window
- ✅ Logs successful SSH logins
- 📁 Maintains separate log files:
  - Failed logins
  - Successful logins
  - Blocked IPs
  - Alerts
  - Incident reports
- 📡 Sends alerts and reports to a remote server via `scp`
- 🔄 Persistent firewall rules using `iptables`

---

## ⚙️ Configuration

You can modify the following parameters in the script:

```python
THRESHOLD = 20          # Number of failed attempts
WINDOW = timedelta(minutes=2)  # Time window
