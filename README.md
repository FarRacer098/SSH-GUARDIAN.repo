# 🛡️ SSH Guardian

**SSH Guardian** is a real-time security monitoring tool designed to detect and prevent brute-force attacks on SSH servers. It continuously analyzes system logs, tracks failed login attempts, blocks malicious IPs, and generates incident reports.

---

## 🚀 Features

* 🔍 Real-time monitoring of SSH logs using `journalctl`
* 🚫 Automatic IP blocking after threshold breach
* 📊 Tracks failed login attempts within a defined time window
* ✅ Logs successful SSH logins
* 📁 Maintains separate log files:

  * Failed logins
  * Successful logins
  * Blocked IPs
  * Alerts
  * Incident reports
* 📡 Sends alerts and reports to a remote server via `scp`
* 🔄 Persistent firewall rules using `iptables`

---

## ⚙️ Configuration

You can modify the following parameters in the script:

```python
THRESHOLD = 20          # Number of failed attempts
WINDOW = timedelta(minutes=2)  # Time window
```

---

## 📂 File Structure

| File Name                  | Description                  |
| -------------------------- | ---------------------------- |
| `cursor.txt`               | Stores last journal cursor   |
| `failed_ssh_login.log`     | Logs failed login attempts   |
| `successful_ssh_login.log` | Logs successful logins       |
| `block_ip.txt`             | Stores blocked IP addresses  |
| `evidence.txt`             | Incident reports             |
| `alert.txt`                | Alerts for successful logins |

---

## 🧠 How It Works

1. Reads SSH logs using `journalctl`
2. Tracks failed login attempts per IP
3. If attempts exceed threshold within time window:

   * Marks it as an attack
   * Blocks the IP using `iptables`
4. Logs successful logins and sends alerts
5. Generates an incident report
6. Sends logs to a remote monitoring server via `scp`

---

## 🖥️ Requirements

* Linux system (Ubuntu/Debian recommended)
* Python 3
* Root privileges
* Installed tools:

  * `iptables`
  * `netfilter-persistent`
  * `journalctl`
  * `scp`

---

## ▶️ Usage

Run the script with root privileges:

```bash
sudo python3 ssh_guardian.py
```

---

## ⚠️ Important Notes

* Must be run as **root**, otherwise it will exit.
* Ensure SSH service name is `ssh` (may vary as `sshd` on some systems).
* Update file paths and remote server credentials in `scp` commands.
* Firewall rules persist using `netfilter-persistent`.

---

## 📡 Remote Server Setup

Make sure:

* SSH access is configured between systems
* Destination path exists:

  ```
  /home/divyansh/report/
  ```
* Passwordless SSH is recommended (use SSH keys)

---

## 🛑 Security Considerations

* Validate IP addresses using `ipaddress` module
* Prevent duplicate firewall rules
* Avoid blocking internal or trusted IPs (can be extended)

---

## 💡 Future Improvements

* Web dashboard for monitoring
* Email/SMS alerts
* Whitelist trusted IPs
* Machine learning-based anomaly detection
* Docker deployment

---

## 👨‍💻 Author

SSH Guardian – Cybersecurity-focused SSH protection tool
