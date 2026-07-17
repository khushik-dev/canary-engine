# app.py — Canary Engine Web Dashboard
# Full authentication system with role-based access control
# Roles: admin (full access) | viewer (read only)
#
# SECURITY: All credentials loaded from .env file
# Never hardcoded in source code

from flask import (Flask, render_template, jsonify,
                   request, session, redirect, url_for, Response)
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict
from dotenv import load_dotenv
import subprocess
import os
import sys
import datetime
import time
import psutil
import zoneinfo

# -------------------------------------------------------
# LOAD ENVIRONMENT VARIABLES
# Reads credentials from .env file
# Falls back to defaults if .env not found
# -------------------------------------------------------
load_dotenv("/home/khushik/canary-engine/.env")

# Add config and scripts to path
sys.path.insert(0, "/home/khushik/canary-engine/config")
sys.path.insert(0, "/home/khushik/canary-engine/scripts")

from settings import LOG_FILE, CANARY_FOLDER, CANARY_FILES

app = Flask(__name__)

# Secret key from environment — used for session encryption
app.secret_key = os.getenv(
    "FLASK_SECRET_KEY",
    "fallback_secret_key_change_this"   # fallback if .env missing
)

# -------------------------------------------------------
# RATE LIMITING
# Tracks failed login attempts per IP address
# After 5 failures — lockout for 5 minutes
# -------------------------------------------------------
login_attempts = defaultdict(list)
MAX_ATTEMPTS   = 5
LOCKOUT_TIME   = 300

def is_rate_limited(ip):
    now = time.time()
    login_attempts[ip] = [
        t for t in login_attempts[ip]
        if now - t < LOCKOUT_TIME
    ]
    return len(login_attempts[ip]) >= MAX_ATTEMPTS

def record_failed_attempt(ip):
    login_attempts[ip].append(time.time())

def get_remaining_lockout(ip):
    if not login_attempts[ip]:
        return 0
    oldest_attempt = min(login_attempts[ip])
    remaining = LOCKOUT_TIME - (time.time() - oldest_attempt)
    return max(0, int(remaining))

# -------------------------------------------------------
# USER CREDENTIALS
# Loaded from .env file — never hardcoded
# Passwords hashed with pbkdf2:sha256
# -------------------------------------------------------
def load_users():
    """
    Loads user credentials from environment variables.
    Passwords are immediately hashed — plain text is
    never stored in memory after this function runs.
    """
    return {
        os.getenv("ADMIN_USERNAME", "admin"): {
            "password": generate_password_hash(
                os.getenv("ADMIN_PASSWORD", "changeme")
            ),
            "pin" : os.getenv("ADMIN_PIN", "000000"),
            "role": "admin"
        },
        os.getenv("VIEWER_USERNAME", "viewer"): {
            "password": generate_password_hash(
                os.getenv("VIEWER_PASSWORD", "changeme")
            ),
            "role": "viewer"
        }
    }

# Load users once at startup
USERS = load_users()

# -------------------------------------------------------
# AUTH HELPERS
# -------------------------------------------------------
def is_logged_in():
    return "username" in session

def is_admin():
    return session.get("role") == "admin"

def is_pin_verified():
    return session.get("pin_verified") == True

def require_login(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return redirect("/login")
        if not is_admin():
            return redirect("/dashboard")
        if not is_pin_verified():
            return redirect("/pin")
        return f(*args, **kwargs)
    return decorated

# -------------------------------------------------------
# SYSTEM HELPERS
# -------------------------------------------------------
def get_log_entries(last_n=50):
    if not os.path.exists(LOG_FILE):
        return ["Log file not found — start watcher.py first"]
    with open(LOG_FILE, "r") as f:
        lines = f.readlines()
    return [line.strip() for line in lines[-last_n:]][::-1]

def get_blocked_ips():
    result = subprocess.run(
        ["sudo", "iptables", "-L", "INPUT", "-n"],
        capture_output=True, text=True
    )
    blocked = []
    for line in result.stdout.splitlines():
        if "DROP" in line:
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[3]
                if ip not in blocked and ip != "source":
                    blocked.append(ip)
    return blocked

def get_canary_status():
    """Returns status of ALL canary files recursively"""
    status = []
    for dirpath, dirnames, filenames in os.walk(CANARY_FOLDER):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(filepath, CANARY_FOLDER)
            if os.path.exists(filepath):
                mtime = os.path.getmtime(filepath)
                modified = datetime.datetime.fromtimestamp(
                    mtime).strftime("%Y-%m-%d %H:%M:%S")
                size = os.path.getsize(filepath)
                status.append({
                    "name"    : rel_path,
                    "exists"  : True,
                    "modified": modified,
                    "size"    : size
                })
            else:
                status.append({
                    "name"    : rel_path,
                    "exists"  : False,
                    "modified": "N/A",
                    "size"    : 0
                })
    return status

def get_system_stats():
    return {
        "cpu"       : psutil.cpu_percent(interval=1),
        "ram"       : psutil.virtual_memory().percent,
        "disk"      : psutil.disk_usage("/").percent,
        "ram_used"  : round(psutil.virtual_memory().used / (1024**3), 1),
        "ram_total" : round(psutil.virtual_memory().total / (1024**3), 1),
        "disk_used" : round(psutil.disk_usage("/").used / (1024**3), 1),
        "disk_total": round(psutil.disk_usage("/").total / (1024**3), 1)
    }

def is_watcher_running():
    result = subprocess.run(
        ["pgrep", "-f", "watcher.py"],
        capture_output=True, text=True
    )
    return result.returncode == 0

def is_samba_running():
    result = subprocess.run(
        ["sudo", "service", "smbd", "status"],
        capture_output=True, text=True
    )
    return "running" in result.stdout.lower()

def is_samba_connected():
    result = subprocess.run(
        ["sudo", "smbstatus", "-S"],
        capture_output=True, text=True
    )
    return "CanaryShare" in result.stdout

def is_email_configured():
    """Check if email alerts are enabled in .env"""
    from dotenv import load_dotenv
    load_dotenv("/home/khushik/canary-engine/.env")
    return os.getenv("EMAIL_ENABLED", "false").lower() == "true"

# -------------------------------------------------------
# AUTH ROUTES
# -------------------------------------------------------
@app.route("/")
def root():
    if not is_logged_in():
        return redirect("/login")
    if is_admin() and is_pin_verified():
        return redirect("/admin")
    return redirect("/dashboard")

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_logged_in():
        return redirect("/")
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        username  = data.get("username", "").strip()
        password  = data.get("password", "").strip()
        client_ip = request.remote_addr

        # Rate limiting check
        if is_rate_limited(client_ip):
            remaining = get_remaining_lockout(client_ip)
            return jsonify({
                "success"  : False,
                "message"  : f"Too many failed attempts. "
                             f"Try again in {remaining} seconds.",
                "locked"   : True,
                "remaining": remaining
            })

        # Credential check
        if username in USERS and check_password_hash(
                USERS[username]["password"], password):

            login_attempts[client_ip] = []
            session["username"]    = username
            session["role"]        = USERS[username]["role"]
            session["pin_verified"] = False

            if USERS[username]["role"] == "admin":
                return jsonify({
                    "success" : True,
                    "redirect": "/pin",
                    "role"    : "admin"
                })
            else:
                return jsonify({
                    "success" : True,
                    "redirect": "/dashboard",
                    "role"    : "viewer"
                })
        else:
            record_failed_attempt(client_ip)
            attempts_left = MAX_ATTEMPTS - len(
                login_attempts[client_ip])
            return jsonify({
                "success": False,
                "message": f"Invalid username or password. "
                           f"{attempts_left} attempts remaining."
            })

    return render_template("login.html")

@app.route("/pin", methods=["GET"])
@require_login
def pin_page():
    if not is_admin():
        return redirect("/dashboard")
    if is_pin_verified():
        return redirect("/admin")
    return render_template("pin.html")

@app.route("/api/verify_pin", methods=["POST"])
@require_login
def verify_pin():
    data     = request.get_json()
    pin      = data.get("pin", "")
    username = session.get("username")

    if USERS[username].get("pin") == pin:
        session["pin_verified"] = True
        return jsonify({"success": True, "redirect": "/admin"})
    else:
        return jsonify({
            "success": False,
            "message": "Invalid PIN — access denied"
        })

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# -------------------------------------------------------
# PAGE ROUTES
# -------------------------------------------------------
@app.route("/dashboard")
@require_login
def dashboard():
    return render_template("dashboard.html",
                           username=session.get("username"),
                           role=session.get("role"))

@app.route("/admin")
@require_admin
def admin():
    return render_template("admin.html",
                           username=session.get("username"))

# -------------------------------------------------------
# API ROUTES — Both roles
# -------------------------------------------------------
@app.route("/api/status")
@require_login
def api_status():
    return jsonify({
        "watcher_running" : is_watcher_running(),
        "samba_running"   : is_samba_running(),
        "samba_connected" : is_samba_connected(),
        "email_enabled"   : is_email_configured(),
        "blocked_ips"     : get_blocked_ips(),
        "canary_files"    : get_canary_status(),
        "system"          : get_system_stats(),
        "timestamp"       : datetime.datetime.now(
                                zoneinfo.ZoneInfo("Asia/Kolkata")
                            ).strftime("%Y-%m-%d %H:%M:%S IST"),
        "role"            : session.get("role")
    })

@app.route("/api/logs")
@require_login
def api_logs():
    return jsonify({"logs": get_log_entries(50)})

# -------------------------------------------------------
# API ROUTES — Admin only
# -------------------------------------------------------
@app.route("/api/start_watcher", methods=["POST"])
@require_admin
def api_start_watcher():
    try:
        check = subprocess.run(
            ["pgrep", "-f", "watcher.py"],
            capture_output=True, text=True
        )
        if check.returncode == 0:
            return jsonify({
                "success": True,
                "message": "Watcher is already running!"
            })
        subprocess.Popen(
            ["/home/khushik/canary-engine/venv/bin/python3",
             "/home/khushik/canary-engine/scripts/watcher.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return jsonify({
            "success": True,
            "message": "Watcher started successfully!"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/stop_watcher", methods=["POST"])
@require_admin
def api_stop_watcher():
    try:
        subprocess.run(
            ["pkill", "-f", "watcher.py"],
            capture_output=True, text=True
        )
        return jsonify({
            "success": True,
            "message": "Watcher stopped"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/connect_samba", methods=["POST"])
@require_admin
def api_connect_samba():
    try:
        subprocess.run(
            ["sudo", "iptables", "-F", "INPUT"],
            capture_output=True, text=True
        )
        subprocess.run(
            ["pkill", "-f", "smbclient"],
            capture_output=True, text=True
        )
        subprocess.Popen(
            ["smbclient", "//localhost/CanaryShare",
             "-U", "REDACTED",
             "-c", "cd /; ls; sleep 300"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return jsonify({
            "success": True,
            "message": "Samba connected!"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/simulate", methods=["POST"])
@require_admin
def api_simulate():
    try:
        subprocess.run(
            ["sudo", "iptables", "-F", "INPUT"],
            capture_output=True, text=True
        )
        subprocess.Popen(
            ["/home/khushik/canary-engine/venv/bin/python3",
             "/home/khushik/canary-engine/scripts/simulate_attack.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return jsonify({
            "success": True,
            "message": "Simulation started!"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/unblock", methods=["POST"])
@require_admin
def api_unblock():
    data = request.get_json()
    ip   = data.get("ip")
    if not ip:
        return jsonify({
            "success": False,
            "message": "No IP provided"
        })
    result = subprocess.run(
        ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        return jsonify({
            "success": True,
            "message": f"IP {ip} unblocked"
        })
    else:
        return jsonify({
            "success": False,
            "message": result.stderr
        })

@app.route("/api/flush", methods=["POST"])
@require_admin
def api_flush():
    result = subprocess.run(
        ["sudo", "iptables", "-F", "INPUT"],
        capture_output=True, text=True
    )
    return jsonify({"success": result.returncode == 0})

@app.route("/api/reset_canary", methods=["POST"])
@require_admin
def api_reset_canary():
    try:
        result = subprocess.run(
            ["/home/khushik/canary-engine/venv/bin/python3",
             "/home/khushik/canary-engine/scripts/reset_canary.py"],
            capture_output=True, text=True
        )
        return jsonify({
            "success": result.returncode == 0,
            "message": "All canary files restored — root + subfolders"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/clear_logs", methods=["POST"])
@require_admin
def api_clear_logs():
    try:
        with open(LOG_FILE, "w") as f:
            f.write(
                f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]"
                f" Log cleared by administrator: "
                f"{session.get('username')}\n"
            )
        return jsonify({
            "success": True,
            "message": "Logs cleared successfully"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/download_logs")
@require_admin
def api_download_logs():
    try:
        with open(LOG_FILE, "r") as f:
            content = f.read()
        return Response(
            content,
            mimetype="text/plain",
            headers={
                "Content-Disposition":
                "attachment; filename=canary_engine.log"
            }
        )
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/full_reset", methods=["POST"])
@require_admin
def api_full_reset():
    try:
        # Step 1 — flush iptables
        subprocess.run(
            ["sudo", "iptables", "-F", "INPUT"],
            capture_output=True, text=True
        )

        # Step 2 — restore all canary files
        subprocess.run(
            ["/home/khushik/canary-engine/venv/bin/python3",
             "/home/khushik/canary-engine/scripts/reset_canary.py"],
            capture_output=True, text=True
        )

        # Step 3 — remove simulation flag
        sim_flag = "/tmp/canary_simulation_mode"
        if os.path.exists(sim_flag):
            os.remove(sim_flag)

        return jsonify({
            "success": True,
            "message": "Full reset complete — all files restored!"
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route("/api/change_password", methods=["POST"])
@require_admin
def api_change_password():
    data         = request.get_json()
    target_user  = data.get("username")
    new_password = data.get("new_password")

    if target_user not in USERS:
        return jsonify({
            "success": False,
            "message": "User not found"
        })
    if not new_password or len(new_password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters"
        })

    # Hash the new password before storing
    USERS[target_user]["password"] = generate_password_hash(
        new_password
    )
    return jsonify({
        "success": True,
        "message": f"Password updated for {target_user}"
    })

if __name__ == "__main__":
    print("=" * 50)
    print("  Canary Engine Dashboard")
    print("  Open browser: http://localhost:5000")
    print("  Credentials loaded from .env file")
    print("=" * 50)
    app.run(debug=False, host="0.0.0.0", port=5000)