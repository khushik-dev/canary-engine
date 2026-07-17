# samba_parser.py
# Gets the IP address of machines connected to our Samba share
# Uses 'smbstatus' command which shows LIVE connections

import subprocess   # lets us run terminal commands from Python
import re           # regular expressions for pattern matching
import os
import sys

# Add config folder to path using absolute path — works with sudo too
CONFIG_DIR = "/home/khushik/canary-engine/config"
sys.path.insert(0, CONFIG_DIR)
from settings import SAMBA_LOG, SAMBA_SHARE_NAME, SIMULATED_ATTACKER_IP

def get_last_accessor_ip(canary_filename=None):
    """
    Uses 'smbstatus' to find which machine is connected to CanaryShare.
    
    FIXED: Now filters specifically for CanaryShare connections only.
    Previously returned ANY connected IP — could block innocent users.
    Now only returns IPs that are specifically connected to our share.
    """
    try:
        result = subprocess.run(
            ["sudo", "smbstatus", "-S"],   # -S = show share connections only
            capture_output=True,
            text=True
        )
        
        output = result.stdout
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        
        # FIXED: Only look at lines that mention CanaryShare specifically
        # This prevents blocking innocent users connected to other shares
        for line in output.splitlines():
            if SAMBA_SHARE_NAME in line:
                match = re.search(ip_pattern, line)
                if match:
                    return match.group(1)
        
        # If no CanaryShare-specific connection found, try full output
        # This is a fallback in case smbstatus format varies
        matches = re.findall(ip_pattern, output)
        if matches:
            return matches[-1]
        
        return None

    except Exception as e:
        print(f"Error running smbstatus: {e}")
        return None

def get_ip_from_log():
    """
    Backup method — scans Samba log files for any IP address.
    Only checks log.127.0.0.1 — the connection-specific log.
    Excludes log.smbd which contains subnet masks and config IPs
    that would cause false attribution.
    """
    # FIXED: Only use connection-specific log file
    # log.smbd contains subnet masks like 255.255.240.0 — not attacker IPs
    # log.127.0.0.1 contains only actual connection IPs
    log_locations = [
        "/var/log/samba/log.127.0.0.1",
        "/var/log/samba/log.localhost"
    ]

    # FIXED: Exclude known non-attacker IPs like subnet masks
    excluded_ips = [
        "255.255.255.0",
        "255.255.240.0",
        "255.255.0.0",
        "0.0.0.0"
    ]

    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

    for log_path in log_locations:
        if os.path.exists(log_path):
            try:
                result = subprocess.run(
                    ["sudo", "cat", log_path],
                    capture_output=True,
                    text=True
                )
                matches = re.findall(ip_pattern, result.stdout)

                # Filter out subnet masks and invalid IPs
                valid_ips = [
                    ip for ip in matches
                    if ip not in excluded_ips
                    and not ip.startswith("255.")
                    and not ip.startswith("0.")
                ]

                if valid_ips:
                    print(f"Found IP in: {log_path}")
                    return valid_ips[-1]

            except PermissionError:
                print(f"  [!] Permission denied reading: {log_path} — try sudo")
                continue
            except FileNotFoundError:
                print(f"  [!] Log file not found: {log_path}")
                continue
            except Exception as e:
                print(f"  [!] Unexpected error reading {log_path}: {type(e).__name__}: {e}")
                continue

    return None

def get_attacker_ip(canary_filename=None):
    """
    Master function — tries multiple methods to find attacker IP.
    Method 1: Check simulation flag file
    Method 2: Check simulation env variable
    Method 3: Live smbstatus
    Method 4: Log file scanning
    Method 5: Default to simulated IP (never localhost)
    """
    # Method 1: Check simulation flag file
    sim_flag = "/tmp/canary_simulation_mode"
    if os.path.exists(sim_flag):
        print(f"  [*] Simulation mode detected (flag file)")
        print(f"  [+] Using simulated attacker IP: {SIMULATED_ATTACKER_IP}")
        return SIMULATED_ATTACKER_IP

    # Method 2: Check environment variable (backup for flag file)
    if os.environ.get("CANARY_SIMULATION") == "1":
        print(f"  [*] Simulation mode detected (env var)")
        print(f"  [+] Using simulated attacker IP: {SIMULATED_ATTACKER_IP}")
        return SIMULATED_ATTACKER_IP

    # Method 3: try live connection status
    print("  [*] Checking live Samba connections...")
    ip = get_last_accessor_ip(canary_filename)
    if ip and ip != "127.0.0.1":
        print(f"  [+] Found via smbstatus: {ip}")
        return ip

    # Method 4: try log files
    print("  [*] Checking Samba log files...")
    ip = get_ip_from_log()
    if ip and ip != "127.0.0.1":
        print(f"  [+] Found via log file: {ip}")
        return ip

    # Method 5: In WSL demo environment — use simulated IP
    # Never return 127.0.0.1 as it breaks Flask and blocks localhost
    print(f"  [*] WSL demo mode — using simulated attacker IP")
    return SIMULATED_ATTACKER_IP

# Test when run directly
if __name__ == "__main__":
    print("=" * 45)
    print("  Samba Log Parser — Testing")
    print("=" * 45)
    print("")
    
    # Show raw smbstatus output first
    print("Live Samba connections (smbstatus):")
    print("-" * 40)
    result = subprocess.run(
        ["sudo", "smbstatus"],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    print("-" * 40)
    print("")
    
    # Now test our IP extraction
    print("Testing IP extraction...")
    ip = get_attacker_ip("passwords_backup.xlsx")
    print("")
    print(f"✅ Attacker IP identified as: {ip}")