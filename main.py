import subprocess
from datetime import datetime, timedelta
import ipaddress
import os
import time

THRESHOLD = 20
WINDOW = timedelta(minutes=2)

#Initializing files
CURSOR_FILE = "cursor.txt"
FAILED_SSH_LOGIN = "failed_ssh_login.log"
SUCCESSFUL_SSH_LOGIN = "successful_ssh_login.log"
BLOCK_IP_FILE = "block_ip.txt"
EVIDENCE_FILE = "evidence.txt"
ALERT_LOGIN_FILE = "alert.txt"

failed_attempts = {}

#Root check
if os.geteuid() != 0:
    print("[ERROR] Run as root!")
    exit(1)

print("\n[SSH Guardian Started]")

while True:
    try:

        attack = False
        
        #Attack report
        incident = {
            "detection_time": "",
            "attacker_ip": "",
            "successful_login": "No",
            "ip_blocked": "No",
            "block_time": "",
            "failed_attempts": 0,
            "threshold limit": THRESHOLD,
            "session_killed": "No"
        }

        # Reading last log 
        last_cursor = None
        if os.path.exists(CURSOR_FILE):
            with open(CURSOR_FILE, "r") as f:
                last_cursor = f.read().strip()


        # =================
        # FETCHING SSH LOGS
        # =================

        command = [
            "journalctl",
            "-u", "ssh",
            "--no-pager",
            "--show-cursor"
        ]

        if last_cursor:
            command.extend(["--after-cursor", last_cursor])

        proc = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)

        ip_to_block = set()
        new_cursor = None
        
        #Opening files to save logs and alert msg
        with open(FAILED_SSH_LOGIN, "a") as fs, \
             open(SUCCESSFUL_SSH_LOGIN, "a") as ss, \
             open(ALERT_LOGIN_FILE, "a") as alert_msg:

            for line in proc.stdout:

                if line.startswith("-- cursor:"):
                    new_cursor = line.split("cursor:")[1].strip()
                    continue

                line_lower = line.lower()

                # ============
                # FAILED LOGIN
                # ============

                if "failed password for" in line_lower:

                    fs.write(line)

                    parts = line.split()
                    ip = parts[parts.index("from")+1] if "from" in parts else None
                    if not ip:
                        continue

                    try:
                        timestamp_str = " ".join(line.split()[:3])
                        year = datetime.now().year
                        timestamp = datetime.strptime(
                            f"{year} {timestamp_str}",
                            "%Y %b %d %H:%M:%S"
                        )
                    except:
                        continue

                    # Track attempts
                    failed_attempts.setdefault(ip, []).append(timestamp)

                    # Remove old entries
                    failed_attempts[ip] = [
                        t for t in failed_attempts[ip]
                        if timestamp - t <= WINDOW
                    ]

                    # Threshold reached
                    if len(failed_attempts[ip]) >= THRESHOLD:
                        ipaddress.ip_address(ip)

                        attack = True
                        ip_to_block.add(ip)

                        incident["attacker_ip"] = ip
                        incident["detection_time"] = timestamp
                        incident["failed_attempts"] = len(failed_attempts[ip])

                # =============
                # SUCCESS LOGIN
                # =============

                if "accepted password for" in line_lower:

                    ss.write(line)

                    parts = line.split()
                    ip = parts[parts.index("from")+1] if "from" in parts else None
                    user = parts[parts.index("for")+1] if "for" in parts else None

                    print(f"[SUCCESS LOGIN] {ip}")

                    try:
                        timestamp_str = " ".join(line.split()[:3])
                        year = datetime.now().year
                        login_timestamp = datetime.strptime(
                            f"{year} {timestamp_str}",
                            "%Y %b %d %H:%M:%S"
                        )
                    except:
                        login_timestamp = None

                    alert_msg.write(
                        f"Successful login by {ip} at {login_timestamp} into USER {user}\n"
                    )
                    
                    #Sending file to server 
                    try:
                        subprocess.run(
                            [
                                "scp",
                                "/home/shivam/SSH_GUARDIAN/alert.txt",
                                "divyansh@192.168.1.16:/home/divyansh/report/"
                            ],
                            timeout=5
                        )
                    except:
                        pass

                    if ip == incident["attacker_ip"]:
                        incident["successful_login"] = "Yes"

        # =========
        # BLOCK IPS
        # =========
        for ip in ip_to_block:

            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", "22", "-s", ip, "-j", "DROP"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            if check.returncode != 0:

                subprocess.run(
                    ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", ip, "-j", "DROP"],
                    check=True
                )

                subprocess.run(
                    ["netfilter-persistent", "save"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

                block_time = datetime.now()

                incident["ip_blocked"] = "Yes"
                incident["block_time"] = block_time

                with open(BLOCK_IP_FILE, "a") as f:
                    f.write(f"{ip} blocked at {block_time}\n")

                print(f"[BLOCKED] {ip}")

        # ===========
        # SAVE CURSOR
        # ===========
        if new_cursor:
            with open(CURSOR_FILE, "w") as f:
                f.write(new_cursor)

        # ===============
        # INCIDENT REPORT
        # ===============
        if attack:
            with open(EVIDENCE_FILE, "a") as f:
                f.write("\n========== INCIDENT REPORT ==========\n")
                for key, value in incident.items():
                    f.write(f"{key} : {value}\n")
                f.write("=====================================\n")

            try:
                subprocess.run(
                    [
                        "scp",
                        "/home/shivam/SSH_GUARDIAN/evidence.txt",
                        "divyansh@192.168.1.16:/home/divyansh/report/"
                    ],
                    timeout=5
                )
            except:
                pass

    except Exception as e:
        print(f"[ERROR] {e}")

    time.sleep(5)