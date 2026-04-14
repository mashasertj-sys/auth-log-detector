import time
import random
import os
from datetime import datetime

LOG_FILE = "activity.log"

open(LOG_FILE, 'w').close()

NORMAL_USERS = ["alice", "bob", "charlie", "dev_ops", "analyst"]
NORMAL_IPS = ["10.0.1.15", "10.0.1.22", "10.0.2.8", "10.0.3.41"]
ATTACKER_IPS = ["203.0.113.50", "198.51.100.22", "192.0.2.99", "45.33.32.156"]
TARGET_USERS = ["root", "admin", "ubuntu", "deploy"]


def generate_normal():
    user = random.choice(NORMAL_USERS)
    ip = random.choice(NORMAL_IPS)
    pid = random.randint(1000, 9999)
    return random.choice([
        f"sshd[{pid}]: Accepted password for {user} from {ip} port 22",
        f"sudo: {user} : COMMAND=/usr/bin/apt update",
        f"systemd[1]: Started Session {random.randint(100, 999)} of user {user}.",
        f"cron[{pid}]: ({user}) CMD (/usr/local/bin/health_check.sh)",
        f"sshd[{pid}]: session closed for user {user}"
    ])

def generate_suspicious():
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(TARGET_USERS)
    pid = random.randint(1000, 9999)
    roll = random.random()
    if roll < 0.4:
        return f"sshd[{pid}]: Failed password for {user} from {ip} port 22"
    elif roll < 0.7:
        return f"sudo: {user} : COMMAND=/bin/cat /etc/shadow"
    elif roll < 0.9:
        return f"sudo: {user} : COMMAND=/usr/sbin/useradd backdoor_user"
    else:
        return f"cron[{pid}]: ({user}) EDIT (root)"

def main():
    print(" Simulator Service started. Generating mixed activity...")
    print(f" Log file: {LOG_FILE}")
    print("  Press Ctrl+C to stop")

    try:
        while True:
            if random.random() < 0.85:
                log_line = generate_normal()
                delay = random.uniform(1.0, 3.0)
            else:
                log_line = generate_suspicious()
                if random.random() < 0.4:
                    for _ in range(random.randint(3, 5)):
                        with open(LOG_FILE, "a") as f:
                            ts = datetime.now().strftime("%b %d %H:%M:%S")
                            f.write(f"{ts} server {log_line}\n")
                        time.sleep(random.uniform(0.2, 0.6))
                    delay = random.uniform(2.0, 4.0)
                    continue
                delay = random.uniform(2.0, 5.0)

            with open(LOG_FILE, "a") as f:
                ts = datetime.now().strftime("%b %d %H:%M:%S")
                f.write(f"{ts} server {log_line}\n")

            time.sleep(delay)
    except KeyboardInterrupt:
        print("\n Simulator stopped.")

if __name__ == "__main__":
    main()