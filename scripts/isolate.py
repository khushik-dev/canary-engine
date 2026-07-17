# isolate.py — Automatic Network Isolation Module
# This is the "action taker" of our project.
# When an attacker's IP is identified, this script
# automatically cuts off that machine from the network using iptables.

import subprocess   # lets Python run terminal commands
import datetime     # for timestamps
import os           # for file paths
import sys

# Add config folder to path using absolute path — works with sudo too
CONFIG_DIR = "/home/khushik/canary-engine/config"
sys.path.insert(0, CONFIG_DIR)

from settings import LOG_FILE

# -------------------------------------------------------
# FUNCTION 1 — write_log()
# Saves a timestamped message to the log file
# and prints it to the terminal simultaneously
# -------------------------------------------------------
def write_log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {message}\n"
    print(entry, end="")
    with open(LOG_FILE, "a") as f:
        f.write(entry)

# -------------------------------------------------------
# FUNCTION 2 — is_valid_ip()
# Validates the IP address format before attempting to block
# Prevents accidental blocking of wrong addresses
# -------------------------------------------------------
def is_valid_ip(ip):
    """
    Validates IP address format.
    Example valid IP   : 192.168.1.105
    Example invalid IP : abc.def.ghi.jkl
    """
    try:
        parts = ip.split(".")
        # IP must have exactly 4 parts separated by dots
        if len(parts) != 4:
            return False
        # Each part must be a number between 0 and 255
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except:
        return False

# -------------------------------------------------------
# FUNCTION — is_already_blocked()
# Checks if an IP is already blocked in iptables
# Prevents duplicate rules from accumulating
# -------------------------------------------------------
def is_already_blocked(ip_address):
    """
    Checks iptables INPUT chain for an existing DROP rule
    for this specific IP address before adding a new one.
    
    Returns True if already blocked, False if not.
    
    Why this matters: Without this check, every canary file
    trigger adds a duplicate rule. 4 files = 4 identical rules.
    This causes kernel slowdown and messy logs.
    """
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n"],
        capture_output=True,
        text=True
    )
    return ip_address in result.stdout

# -------------------------------------------------------
# FUNCTION 3 — block_ip()
# MAIN FUNCTION — blocks attacker's IP using iptables
# iptables is a Linux firewall tool that controls
# which network traffic is allowed or blocked
# -------------------------------------------------------
def block_ip(ip_address):
    """
    Blocks ALL network traffic from a specific IP address.

    Command it runs internally:
    sudo iptables -I INPUT -s <IP> -j DROP

    -I INPUT = Insert rule at top of INPUT chain (highest priority)
    -s       = source IP address to block
    -j DROP  = silently discard all packets from this IP
    """
    # Validate IP exists
    if not ip_address:
        write_log("ERROR: No IP address provided to block")
        return False

    # Validate IP format
    if not is_valid_ip(ip_address):
        write_log(f"ERROR: Invalid IP format: {ip_address}")
        return False

    # FIXED: Check if already blocked before adding duplicate rule
    if is_already_blocked(ip_address):
        write_log(f"INFO: IP {ip_address} is already blocked — skipping duplicate rule")
        return True
    
    # Never block localhost — it would break Flask dashboard
    # and prevent any further network communication
    if ip_address == "127.0.0.1":
        write_log(f"INFO: Skipping block of localhost (127.0.0.1) — protected IP")
        write_log(f"INFO: In production, attacker would have a different IP")
        return True

    write_log(f"ISOLATION: Attempting to block IP: {ip_address}")

    # Build the iptables block command
    block_command = [
        "sudo",            # run with administrator privileges
        "iptables",        # Linux firewall tool
        "-I",              # Insert rule at top (highest priority)
        "INPUT",           # apply to incoming traffic
        "-s", ip_address,  # from this source IP address
        "-j", "DROP"       # silently drop all matching packets
    ]

    try:
        result = subprocess.run(
            block_command,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            # returncode 0 = command succeeded
            write_log(f"SUCCESS: IP {ip_address} BLOCKED via iptables")
            write_log(f"ISOLATION COMPLETE: Attacker cut off from network")

            # Save rules persistently so they survive reboot
            save_iptables_rules()
            return True
        else:
            write_log(f"ERROR: iptables command failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        # iptables took too long — network may be overloaded
        write_log("ERROR: iptables command timed out after 10 seconds")
        write_log("ACTION: Check if iptables service is responsive")
        return False
    except PermissionError:
        # Script not running with sufficient privileges
        write_log("ERROR: Permission denied — iptables requires sudo privileges")
        write_log("ACTION: Run watcher with sudo or configure sudoers file")
        return False
    except FileNotFoundError:
        # iptables binary not found on system
        write_log("ERROR: iptables not found on this system")
        write_log("ACTION: Install with: sudo apt install iptables")
        return False
    except Exception as e:
        # Catch any other unexpected errors with full details
        write_log(f"ERROR: Unexpected error type={type(e).__name__} | details={e}")
        write_log("ACTION: Check system logs for more information")
        return False

# -------------------------------------------------------
# FUNCTION 4 — unblock_ip()
# Removes the network block after investigation is complete
# Use this once you have confirmed the threat is neutralized
# -------------------------------------------------------
def unblock_ip(ip_address):
    """
    Removes the iptables block on a specific IP address.

    Command it runs internally:
    sudo iptables -D INPUT -s <IP> -j DROP

    -D = Delete the rule (opposite of -I which inserts)
    """
    write_log(f"UNBLOCK: Removing network block on IP: {ip_address}")

    unblock_command = [
        "sudo", "iptables",
        "-D",              # Delete the matching rule
        "INPUT",
        "-s", ip_address,
        "-j", "DROP"
    ]

    try:
        result = subprocess.run(
            unblock_command,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            write_log(f"SUCCESS: IP {ip_address} has been UNBLOCKED")
            # Save updated rules persistently
            save_iptables_rules()
            return True
        else:
            write_log(f"ERROR: Could not unblock {ip_address}: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        write_log("ERROR: Unblock command timed out")
        return False
    except PermissionError:
        write_log("ERROR: Permission denied — requires sudo privileges")
        return False
    except FileNotFoundError:
        write_log("ERROR: iptables not found on this system")
        return False
    except Exception as e:
        write_log(f"ERROR: Unexpected error type={type(e).__name__} | details={e}")
        return False
    
def save_iptables_rules():
    """
    Saves current iptables rules to disk so they
    survive system reboots.
    Uses iptables-save to write rules to the
    persistent storage file.
    """
    try:
        result = subprocess.run(
            ["sudo", "iptables-save"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            # Write rules to persistent file
            with open("/etc/iptables/rules.v4", "w") as f:
                f.write(result.stdout)
            write_log("INFO: iptables rules saved persistently")
        else:
            write_log(f"WARNING: Could not save iptables rules: "
                      f"{result.stderr}")
    except Exception as e:
        write_log(f"WARNING: iptables-save error: {e}")    

# -------------------------------------------------------
# FUNCTION 5 — list_blocked_ips()
# Displays all currently active iptables DROP rules
# Use this to verify which IPs are currently blocked
# -------------------------------------------------------
def list_blocked_ips():
    """
    Lists all current iptables DROP rules in the INPUT chain.
    Shows which IP addresses are currently blocked.
    """
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"],
        capture_output=True,
        text=True
    )
    print("\nCurrent blocked IPs (iptables rules):")
    print("-" * 45)
    print(result.stdout)
    print("-" * 45)

# -------------------------------------------------------
# TEST — runs only when this file is executed directly
# -------------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  isolate.py — Network Isolation Module Test")
    print("=" * 50)
    print("")

    test_ip = "127.0.0.1"

    print(f"Step 1: Validating IP: {test_ip}")
    if is_valid_ip(test_ip):
        print(f"  ✅ IP format is valid")

    print(f"\nStep 2: Blocking IP: {test_ip}")
    success = block_ip(test_ip)

    if success:
        print(f"\nStep 3: Verifying block...")
        list_blocked_ips()

        print(f"\nStep 4: Unblocking IP: {test_ip}")
        unblock_ip(test_ip)

        print(f"\nStep 5: Verifying unblock...")
        list_blocked_ips()

        print("\n✅ isolate.py working perfectly!")
    else:
        print("\n❌ Block failed — check sudo permissions")