# email_alert.py — Email Alert System
# Sends an email notification when a canary file is triggered
# Uses Gmail SMTP with App Password authentication

import smtplib
import os
import sys
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Track last email time to prevent spam
# Only send one email per attack (60 second cooldown)
_last_email_time = 0
EMAIL_COOLDOWN_SECONDS = 60

# Add config to path
sys.path.insert(0, "/home/khushik/canary-engine/config")

# Load email settings from .env file
from dotenv import load_dotenv
load_dotenv("/home/khushik/canary-engine/.env")

EMAIL_ENABLED     = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
EMAIL_SENDER      = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD    = os.getenv("EMAIL_PASSWORD", "")
EMAIL_RECEIVER    = os.getenv("EMAIL_RECEIVER", "")
EMAIL_SMTP_SERVER = os.getenv("EMAIL_SMTP_SERVER", "smtp.gmail.com")
EMAIL_SMTP_PORT   = int(os.getenv("EMAIL_SMTP_PORT", "587"))

def send_alert_email(filename, event_type, attacker_ip, folder=None):
    """
    Sends an email alert when a canary file is triggered.

    Parameters:
    - filename    : name of the canary file that was touched
    - event_type  : what happened (MODIFIED, DELETED, etc)
    - attacker_ip : IP address of the suspected attacker
    - folder      : subfolder the file is in (optional)
    """
    global _last_email_time

    if not EMAIL_ENABLED:
        print("  [!] Email alerts disabled in settings")
        return False

    # Cooldown check — prevent email spam during multi-file attacks
    import time
    now = time.time()
    if now - _last_email_time < EMAIL_COOLDOWN_SECONDS:
        print(f"  [!] Email cooldown active — skipping duplicate alert")
        return False

    _last_email_time = now

    try:
        # Build full file path for display
        if folder and folder != ".":
            full_path = f"{folder}/{filename}"
        else:
            full_path = filename

        # Get current timestamp
        timestamp = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # ── EMAIL SUBJECT ──
        subject = (
            f"🚨 RANSOMWARE ALERT — Canary Triggered: {filename}"
        )

        # ── EMAIL BODY (HTML) ──
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;
                     background: #0a0e1a;
                     color: #e0e6f0;
                     padding: 20px;">

            <div style="max-width: 600px;
                        margin: 0 auto;
                        background: #0d1117;
                        border: 2px solid #da3633;
                        border-radius: 8px;
                        padding: 24px;">

                <!-- HEADER -->
                <div style="text-align: center;
                            margin-bottom: 24px;">
                    <h1 style="color: #f85149;
                               font-size: 24px;
                               margin: 0;">
                        🛡️ CANARY ENGINE ALERT
                    </h1>
                    <p style="color: #8b949e;
                              font-size: 12px;
                              margin: 4px 0 0 0;">
                        Cisco CCST Cybersecurity Project
                    </p>
                </div>

                <!-- ALERT BOX -->
                <div style="background: #2d1117;
                            border: 1px solid #da3633;
                            border-radius: 6px;
                            padding: 16px;
                            margin-bottom: 20px;">
                    <h2 style="color: #f85149;
                               font-size: 16px;
                               margin: 0 0 12px 0;">
                        ⚠️ POSSIBLE RANSOMWARE DETECTED
                    </h2>
                    <table style="width: 100%;
                                  border-collapse: collapse;
                                  font-size: 13px;">
                        <tr>
                            <td style="color: #8b949e;
                                       padding: 6px 0;
                                       width: 140px;">
                                Timestamp
                            </td>
                            <td style="color: #e0e6f0;
                                       padding: 6px 0;
                                       font-weight: bold;">
                                {timestamp}
                            </td>
                        </tr>
                        <tr>
                            <td style="color: #8b949e;
                                       padding: 6px 0;">
                                Canary File
                            </td>
                            <td style="color: #f85149;
                                       padding: 6px 0;
                                       font-weight: bold;">
                                {full_path}
                            </td>
                        </tr>
                        <tr>
                            <td style="color: #8b949e;
                                       padding: 6px 0;">
                                Event Type
                            </td>
                            <td style="color: #e3b341;
                                       padding: 6px 0;
                                       font-weight: bold;">
                                {event_type}
                            </td>
                        </tr>
                        <tr>
                            <td style="color: #8b949e;
                                       padding: 6px 0;">
                                Attacker IP
                            </td>
                            <td style="color: #f85149;
                                       padding: 6px 0;
                                       font-weight: bold;">
                                {attacker_ip}
                            </td>
                        </tr>
                        <tr>
                            <td style="color: #8b949e;
                                       padding: 6px 0;">
                                Action Taken
                            </td>
                            <td style="color: #3fb950;
                                       padding: 6px 0;
                                       font-weight: bold;">
                                ✅ IP Automatically Blocked
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- WHAT TO DO -->
                <div style="background: #0d2f1f;
                            border: 1px solid #238636;
                            border-radius: 6px;
                            padding: 16px;
                            margin-bottom: 20px;">
                    <h3 style="color: #3fb950;
                               font-size: 14px;
                               margin: 0 0 8px 0;">
                        📋 Immediate Actions Required
                    </h3>
                    <ol style="color: #c9d1d9;
                               font-size: 13px;
                               margin: 0;
                               padding-left: 20px;">
                        <li style="margin-bottom: 6px;">
                            Log into the Canary Engine dashboard
                        </li>
                        <li style="margin-bottom: 6px;">
                            Verify the attacker IP:
                            <strong style="color: #f85149;">
                                {attacker_ip}
                            </strong>
                            is blocked
                        </li>
                        <li style="margin-bottom: 6px;">
                            Check which other files may have
                            been affected
                        </li>
                        <li style="margin-bottom: 6px;">
                            Investigate the source machine
                            at {attacker_ip}
                        </li>
                        <li>
                            Document the incident for reporting
                        </li>
                    </ol>
                </div>

                <!-- FOOTER -->
                <div style="text-align: center;
                            color: #8b949e;
                            font-size: 11px;
                            border-top: 1px solid #1e3a5f;
                            padding-top: 16px;">
                    <p style="margin: 0;">
                        This is an automated alert from
                        Canary Engine Detection System
                    </p>
                    <p style="margin: 4px 0 0 0;">
                        Cisco CCST Cybersecurity Internship Project
                    </p>
                </div>

            </div>
        </body>
        </html>
        """

        # ── PLAIN TEXT FALLBACK ──
        text_body = f"""
CANARY ENGINE — RANSOMWARE ALERT

Timestamp  : {timestamp}
File       : {full_path}
Event      : {event_type}
Attacker IP: {attacker_ip}
Action     : IP Automatically Blocked

Immediate actions required:
1. Log into the Canary Engine dashboard
2. Verify {attacker_ip} is blocked
3. Check which other files may be affected
4. Investigate the source machine
5. Document the incident

-- Canary Engine Detection System
   Cisco CCST Cybersecurity Project
        """

        # ── BUILD EMAIL ──
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = EMAIL_RECEIVER

        # Attach both plain text and HTML versions
        # Email clients will show HTML if supported,
        # plain text otherwise
        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        # ── SEND EMAIL ──
        print(f"  [*] Sending alert email to {EMAIL_RECEIVER}...")

        with smtplib.SMTP(EMAIL_SMTP_SERVER,
                          EMAIL_SMTP_PORT) as server:
            server.ehlo()
            server.starttls()          # encrypt the connection
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(
                EMAIL_SENDER,
                EMAIL_RECEIVER,
                msg.as_string()
            )

        print(f"  [+] Alert email sent successfully!")
        return True

    except smtplib.SMTPAuthenticationError:
        print("  [!] EMAIL ERROR: Authentication failed")
        print("  [!] Check your Gmail app password in settings.py")
        return False
    except smtplib.SMTPException as e:
        print(f"  [!] EMAIL ERROR: SMTP error: {e}")
        return False
    except Exception as e:
        print(f"  [!] EMAIL ERROR: Unexpected error: {e}")
        return False

# Test when run directly
if __name__ == "__main__":
    print("Testing email alert system...")
    print(f"Sending test email to: {EMAIL_RECEIVER}")
    print("")

    success = send_alert_email(
        filename    = "passwords_backup.xlsx",
        event_type  = "MODIFIED",
        attacker_ip = "192.168.1.100",
        folder      = "root"
    )

    if success:
        print("")
        print("✅ Test email sent! Check your inbox.")
    else:
        print("")
        print("❌ Email failed — check settings.py credentials")