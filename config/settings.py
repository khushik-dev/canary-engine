# config/settings.py — Central Configuration File
# All project settings live here in one place.
# FIXED: Using absolute path instead of ~ to work correctly
# whether run as normal user or with sudo

import os
import pwd

# Get the actual logged-in username even when running with sudo
# This prevents ~ from expanding to /root/ when sudo is used
def get_real_home():
    """
    Returns the real home directory of the logged-in user.
    Works correctly even when script is run with sudo.
    """
    # Try SUDO_USER first — set by sudo to original username
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return pwd.getpwnam(sudo_user).pw_dir
    # Fall back to current user's home
    return os.path.expanduser("~")

# --- BASE PATHS ---
HOME_DIR      = get_real_home()
BASE_DIR      = os.path.join(HOME_DIR, "canary-engine")
CANARY_FOLDER = os.path.join(BASE_DIR, "canary_files")
LOG_FILE      = os.path.join(BASE_DIR, "logs", "watcher.log")
SCRIPTS_DIR   = os.path.join(BASE_DIR, "scripts")
CONFIG_DIR    = os.path.join(BASE_DIR, "config")

# --- SAMBA LOG LOCATION ---
SAMBA_LOG = "/var/log/samba/log.127.0.0.1"

# --- CANARY FILES LIST ---
# Root level canary files
CANARY_FILES = [
    "passwords_backup.xlsx",
    "important_documents.docx",
    "client_data_2024.pdf",
    "financial_records.zip"
]

# Subfolder canary files — watched recursively
# Format: {subfolder: [files inside it]}
CANARY_SUBFOLDERS = {
    "HR": [
        "employee_salaries.xlsx",
        "employee_records.docx"
    ],
    "Finance": [
        "financial_records.xlsx",
        "budget_report.pdf"
    ],
    "Management": [
        "strategy_2026.docx",
        "board_minutes.pdf"
    ]
}

# All canary filenames combined (used for quick lookup)
ALL_CANARY_FILES = CANARY_FILES + [
    filename
    for files in CANARY_SUBFOLDERS.values()
    for filename in files
]

# --- ALERT SETTINGS ---
ALERT_COOLDOWN_SECONDS = 6

# --- SAMBA SHARE NAME ---
SAMBA_SHARE_NAME = "CanaryShare"

# --- SIMULATION SETTINGS ---
# Fake attacker IP used during simulations
# Using a non-localhost IP so dashboard can display it correctly
SIMULATED_ATTACKER_IP = "192.168.1.100"
SIMULATION_MODE = False   # set to True by simulate_attack.py

# --- EMAIL ALERT SETTINGS ---
EMAIL_ENABLED      = True
EMAIL_SENDER       = "REDACTED"    # your gmail address
EMAIL_PASSWORD     = "REDACTED"     # your 16-char app password
EMAIL_RECEIVER     = "REDACTED"    # where to send
EMAIL_SMTP_SERVER  = "smtp.gmail.com"
EMAIL_SMTP_PORT    = 587

# --- ADMIN SETTINGS ---
# PIN and credentials are loaded from .env file via app.py
# Never hardcode credentials here