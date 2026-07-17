# simulate_attack.py — Safe Ransomware Simulator
# This script SAFELY simulates ransomware-like behavior
# No real malware — only modifies text files harmlessly
# Used to test our canary detection system

import os
import time
import random
import string
import sys

# Add config folder to path using absolute path — works with sudo too
sys.path.insert(0, "/home/khushik/canary-engine/config")
from settings import CANARY_FOLDER, SIMULATED_ATTACKER_IP

# Simulation flag file — tells samba_parser to use fake attacker IP
# This prevents 127.0.0.1 from being blocked (which would break Flask)
SIMULATION_FLAG = "/tmp/canary_simulation_mode"

def fake_encrypt(filepath):
    """
    Simulates ransomware encrypting a file.
    Real ransomware replaces file content with encrypted bytes.
    We replace it with random harmless characters to simulate this.
    """
    print(f"  [ATTACK] Modifying: {os.path.basename(filepath)}")
    
    # Generate random fake "encrypted" content — completely harmless
    fake_content = ''.join(
        random.choices(string.ascii_letters + string.digits, k=256)
    )
    
    # Overwrite the file with garbage content
    with open(filepath, "w") as f:
        f.write(fake_content)
    
    # Small delay between files — real ransomware also processes one by one
    time.sleep(1)

def run_simulation():
    print("")
    print("=" * 50)
    print("  RANSOMWARE SIMULATION STARTING")
    print(f"  Simulated attacker IP: {SIMULATED_ATTACKER_IP}")
    print("  (100% safe — no real malware)")
    print("=" * 50)
    print("")

    # Create simulation flag — tells samba_parser to use fake IP
    # Using both file flag AND environment variable for reliability
    try:
        with open(SIMULATION_FLAG, "w") as f:
            f.write(SIMULATED_ATTACKER_IP)
        print(f"  [*] Simulation flag created: {SIMULATION_FLAG}")
    except Exception as e:
        print(f"  [!] Could not create flag file: {e}")

    # Set environment variable as backup
    os.environ["CANARY_SIMULATION"] = "1"
    print(f"  [*] Simulation mode activated — attacker IP: {SIMULATED_ATTACKER_IP}")

    # Find ALL files recursively — including subfolders
    # os.walk() traverses entire folder tree
    all_files = []
    for dirpath, dirnames, filenames in os.walk(CANARY_FOLDER):
        for filename in filenames:
            all_files.append(os.path.join(dirpath, filename))

    if not all_files:
        print("ERROR: No files found in canary folder!")
        # Remove flag if no files found
        if os.path.exists(SIMULATION_FLAG):
            os.remove(SIMULATION_FLAG)
        return

    print(f"  Found {len(all_files)} files across all folders")
    print("  Beginning simulated attack...\n")

    # Modify each file — mimicking ransomware encryption behavior
    for filepath in all_files:
        fake_encrypt(filepath)

    print("")
    print("=" * 50)
    print("  SIMULATION COMPLETE")
    print(f"  Attacker IP {SIMULATED_ATTACKER_IP} should be blocked!")
    print("  Check the watcher terminal and dashboard!")
    print("=" * 50)

    # Remove simulation flag after 30 seconds
    # Keeps it active long enough for watcher to process all files
    time.sleep(30)
    if os.path.exists(SIMULATION_FLAG):
        os.remove(SIMULATION_FLAG)
    print("  [*] Simulation mode deactivated")

if __name__ == "__main__":
    # Clean up any leftover flag from previous run
    if os.path.exists(SIMULATION_FLAG):
        os.remove(SIMULATION_FLAG)

    run_simulation()

    print("")
    print("=" * 50)
    print("  NOTE: Run reset_canary.py to restore files")
    print("  after stopping the watcher.")
    print("=" * 50)