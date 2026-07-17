# watcher.py — Canary File Watcher
# This is the MAIN script of our project.
# It watches the canary_files folder 24/7 and alerts us the moment anything changes.

# --- IMPORTS ---
# Think of imports like loading tools into your toolbox before starting work

import inotify_simple    # the tool that lets us watch files for changes (Linux Inotify)
import os                # lets us work with file paths and folders
import datetime          # lets us get the current date and time for logging
import sys               # lets us access system-level functions (like file paths and exiting the script)
import logging           # Python's built-in logging system
import subprocess        # lets us run system commands like service status checks
from logging.handlers import RotatingFileHandler  # auto-rotates log files by size

# Add config and scripts folders to path using absolute paths — works with sudo too
sys.path.insert(0, "/home/khushik/canary-engine/config")
sys.path.insert(0, "/home/khushik/canary-engine/scripts")

from settings import (CANARY_FOLDER, LOG_FILE, CANARY_FILES,
                      ALERT_COOLDOWN_SECONDS, ALL_CANARY_FILES)
from samba_parser import get_attacker_ip
from isolate import block_ip

# Import email alert — wrapped in try/except so
# watcher still works even if email isn't configured
try:
    from email_alert import send_alert_email
    EMAIL_ALERTS_ENABLED = True
except ImportError:
    EMAIL_ALERTS_ENABLED = False
    print("  [!] email_alert.py not found — email alerts disabled")

# Tracks recently alerted files to prevent duplicate alerts
# Key = filename, Value = timestamp of last alert
recent_alerts = {}

# -------------------------------------------------------
# LOGGING SETUP — Rotating Log File System
# Replaces manual write_log() with Python's built-in logging
# RotatingFileHandler automatically:
#   - Creates a new log file when current one hits 5MB
#   - Keeps last 5 log files as backup
#   - Prevents disk from filling up in long-running deployments
# -------------------------------------------------------
def setup_logger():
    """
    Sets up a rotating log system.
    Max file size: 5MB per file
    Max backup files: 5 (so max 25MB total log storage)
    Format: [2026-07-01 21:33:10] MESSAGE
    """
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    logger = logging.getLogger("CanaryEngine")
    logger.setLevel(logging.INFO)

    # Rotating file handler — auto-manages log file size
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,   # 5MB max per log file
        backupCount=5                 # keep last 5 rotated files
    )

    # Console handler — prints to terminal simultaneously
    console_handler = logging.StreamHandler()

    # Format: [2026-07-01 21:33:10] MESSAGE
   # Set logger to use IST timezone
    import zoneinfo
    logging.Formatter.converter = lambda *args: \
        datetime.datetime.now(
            zoneinfo.ZoneInfo("Asia/Kolkata")
        ).timetuple()

    formatter = logging.Formatter("[%(asctime)s] %(message)s",
                                   datefmt="%Y-%m-%d %H:%M:%S IST")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# Initialize logger — used throughout this script
logger = setup_logger()

def write_log(message):
    """
    Wrapper function — keeps all existing write_log() calls working.
    Now routes through the rotating logger instead of manual file writes.
    """
    logger.info(message)

# -------------------------------------------------------
# FUNCTION 2 — get_event_type()
# Inotify gives us a number (called a "mask") to describe what happened
# This function translates that number into a human-readable word
# Example: mask 2 becomes "MODIFIED"
# -------------------------------------------------------
def get_event_type(mask):
    if mask & inotify_simple.flags.MODIFY:
        return "MODIFIED"
    elif mask & inotify_simple.flags.CREATE:
        return "CREATED"
    elif mask & inotify_simple.flags.DELETE:
        return "DELETED"
    elif mask & inotify_simple.flags.MOVED_FROM:
        return "RENAMED (old name)"
    elif mask & inotify_simple.flags.MOVED_TO:
        return "RENAMED (new name)"
    else:
        return "UNKNOWN EVENT"

# -------------------------------------------------------
# FUNCTION 3 — handle_alert()
# This is called ONLY when a canary file specifically is touched
# It logs a serious alert and prints a big warning to the terminal
# Automatic IP blocking handled via isolate.py block_ip()
# -------------------------------------------------------
def handle_alert(filename, event_type):
    # Check cooldown — prevent duplicate alerts for the same file
    now = datetime.datetime.now()
    if filename in recent_alerts:
        seconds_since_last = (now - recent_alerts[filename]).total_seconds()
        if seconds_since_last < ALERT_COOLDOWN_SECONDS:
            return
    
    recent_alerts[filename] = now
    
    write_log(f"!!! CANARY TRIGGERED !!! Event={event_type} | File={filename}")
    write_log(f"POSSIBLE RANSOMWARE DETECTED — Immediate investigation required")
    
    # Step 1 — Identify the attacker's IP address
    write_log("Identifying attacker IP...")
    attacker_ip = get_attacker_ip(filename)
    write_log(f"Attacker IP identified: {attacker_ip}")
    
    # Step 2 — Automatically block the attacker
    write_log("Initiating automatic network isolation...")
    success = block_ip(attacker_ip)
    
    if success:
        write_log(f"NETWORK ISOLATION COMPLETE — {attacker_ip} has been cut off")
    else:
        write_log(f"ISOLATION FAILED — Manual action required for IP: {attacker_ip}")

    # Step 3 — Send email alert to security team
    if EMAIL_ALERTS_ENABLED:
        try:
            # Get subfolder if file is in subdirectory
            folder = os.path.dirname(
                os.path.relpath(
                    os.path.join(CANARY_FOLDER, filename),
                    CANARY_FOLDER
                )
            )
            send_alert_email(
                filename    = filename,
                event_type  = event_type,
                attacker_ip = attacker_ip,
                folder      = folder if folder != "." else "root"
            )
            write_log("Email alert sent to security team")
        except Exception as e:
            write_log(f"WARNING: Email alert failed: {e}")
    else:
        write_log("Email alerts not configured — skipping")
    
    # Print a large visible warning box in the terminal
    print("")
    print("=" * 55)
    print("        *** RANSOMWARE ALERT ***")
    print(f"  File      : {filename}")
    print(f"  Event     : {event_type}")
    print(f"  Attacker  : {attacker_ip}")
    if success:
        print(f"  Status    : ✅ BLOCKED AUTOMATICALLY")
    else:
        print(f"  Status    : ❌ BLOCK FAILED — act manually")
    print("=" * 55)
    print("")

# -------------------------------------------------------
# FUNCTION 4 — start_watching()
# This is the MAIN function — it starts the watcher and
# keeps it running forever until you press Ctrl+C
# -------------------------------------------------------
def check_samba_running():
    """
    Verifies Samba is running before starting the watcher.
    If Samba is down, IP attribution will fail silently —
    causing the system to default to 127.0.0.1 and potentially
    block legitimate local connections.
    """
    result = subprocess.run(
        ["sudo", "service", "smbd", "status"],
        capture_output=True,
        text=True
    )
    if "running" in result.stdout.lower():
        write_log("Samba status : RUNNING ✓")
        return True
    else:
        write_log("WARNING: Samba does not appear to be running!")
        write_log("ACTION  : Start Samba with: sudo service smbd start")
        write_log("WARNING : IP attribution may fail without Samba running")
        print("")
        print("⚠️  WARNING: Samba is not running!")
        print("   Start it with: sudo service smbd start")
        print("   Continuing anyway — IP attribution may not work correctly")
        print("")
        return False

def start_watching():
    # First make sure the logs folder exists
    # exist_ok=True means "don't give an error if it already exists"
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    # Confirm the canary folder actually exists before we try to watch it
    if not os.path.exists(CANARY_FOLDER):
        print(f"ERROR: Canary folder not found: {CANARY_FOLDER}")
        print("Make sure you created the canary_files folder first.")
        sys.exit(1)   # exit the script with error code 1

    # Check Samba is running before starting
    # If Samba is down, we can still detect file changes
    # but won't be able to identify the attacker's IP correctly
    check_samba_running()
    
    write_log("=" * 50)
    write_log("Canary Engine STARTED")
    write_log(f"Watching folder : {CANARY_FOLDER}")
    write_log(f"Canary files    : {len(ALL_CANARY_FILES)} files being monitored")
    write_log("=" * 50)
    
    # Create the inotify instance — this is our "security camera"
    inotify = inotify_simple.INotify()

    # Tell inotify WHICH events to listen for using a bitmask
    # The | symbol combines multiple flags together
    watch_flags = (
        inotify_simple.flags.MODIFY    |   # file content was changed
        inotify_simple.flags.CREATE    |   # a new file was created
        inotify_simple.flags.DELETE    |   # a file was deleted
        inotify_simple.flags.MOVED_FROM|   # a file was renamed (before)
        inotify_simple.flags.MOVED_TO      # a file was renamed (after)
    )

    # FIXED: Watch recursively — monitors ALL subfolders too
    # Maps watch descriptor (wd) to folder path
    # so we know which folder an event came from
    watch_descriptors = {}

    def add_watches_recursively(folder):
        """
        Adds inotify watches to a folder AND all its subfolders.
        Called once at startup and again when new subfolders are created.
        """
        for dirpath, dirnames, filenames in os.walk(folder):
            wd = inotify.add_watch(dirpath, watch_flags)
            watch_descriptors[wd] = dirpath
            write_log(f"Watching: {dirpath}")

    # Register canary folder and all subfolders
    add_watches_recursively(CANARY_FOLDER)

    write_log(f"Watching {len(watch_descriptors)} "
              f"folder(s) recursively")
    write_log("Watcher is ACTIVE. Press Ctrl+C to stop.")
    print("")
    
    # --- MAIN LOOP ---
    # This loop runs FOREVER
    # inotify.read() pauses and WAITS here until something happens
    # It uses almost zero CPU while waiting — very efficient
    try:
        while True:
            events = inotify.read()   # pauses here until a file event occurs

            for event in events:
                filename   = event.name
                event_type = get_event_type(event.mask)

                # Get the folder this event came from
                # using the watch descriptor map
                folder = watch_descriptors.get(
                    event.wd, CANARY_FOLDER)
                filepath = os.path.join(folder, filename)

                # Log EVERY event with full path
                write_log(f"Event detected | Type={event_type} "
                          f"| File={filepath}")

                # If a new directory was created — watch it too!
                # This handles ransomware that creates new subfolders
                if (event.mask & inotify_simple.flags.CREATE
                        and os.path.isdir(filepath)):
                    wd = inotify.add_watch(filepath, watch_flags)
                    watch_descriptors[wd] = filepath
                    write_log(f"New folder detected — "
                              f"now watching: {filepath}")

                # Check if it's one of our canary files
                # ALL_CANARY_FILES includes root + subfolder files
                if filename in ALL_CANARY_FILES:
                    handle_alert(filename, event_type)
                else:
                    write_log(f"Non-canary file event "
                              f"(monitoring only): {filename}")
    
    except KeyboardInterrupt:
        # This runs when you press Ctrl+C to stop the script
        print("")
        write_log("Canary Engine STOPPED by user.")
        print("Watcher stopped cleanly.")

# --- ENTRY POINT ---
# This line means: only run start_watching() if this file
# is run directly (not imported by another script)
if __name__ == "__main__":
    start_watching()