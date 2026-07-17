# reset_canary.py — Restore ALL canary files after a test
# Run this AFTER stopping watcher.py with Ctrl+C
# Restores both root level AND subfolder canary files

import os
import sys

sys.path.insert(0, "/home/khushik/canary-engine/config")
from settings import CANARY_FOLDER, CANARY_SUBFOLDERS

def reset_canary_files():
    # Root level canary files
    root_originals = {
        "passwords_backup.xlsx"   : "Confidential - Do Not Share",
        "financial_records.zip"   : "Q4 Financial Summary 2024",
        "client_data_2024.pdf"    : "Client Database Export",
        "important_documents.docx": "System Administrator Credentials"
    }

    # Subfolder canary files
    subfolder_originals = {
        "HR": {
            "employee_salaries.xlsx": "HR Salaries 2026 - Confidential",
            "employee_records.docx" : "HR Employee Records - Do Not Share"
        },
        "Finance": {
            "financial_records.xlsx": "Finance Accounts 2026 - Confidential",
            "budget_report.pdf"     : "Finance Budget Report - Restricted"
        },
        "Management": {
            "strategy_2026.docx": "Management Strategy 2026 - Top Secret",
            "board_minutes.pdf" : "Management Board Minutes - Confidential"
        }
    }

    print("")
    print("=" * 50)
    print("  RESTORING ALL CANARY FILES")
    print("=" * 50)

    # Restore root files
    print("\n  Root folder:")
    for filename, content in root_originals.items():
        filepath = os.path.join(CANARY_FOLDER, filename)
        with open(filepath, "w") as f:
            f.write(content)
        print(f"  [RESTORED] {filename}")

    # Restore subfolder files
    for subfolder, files in subfolder_originals.items():
        print(f"\n  {subfolder}/")
        subfolder_path = os.path.join(CANARY_FOLDER, subfolder)

        # Create subfolder if it doesn't exist
        os.makedirs(subfolder_path, exist_ok=True)

        for filename, content in files.items():
            filepath = os.path.join(subfolder_path, filename)
            with open(filepath, "w") as f:
                f.write(content)
            print(f"  [RESTORED] {subfolder}/{filename}")

    print("")
    print("  ✅ All canary files restored!")
    print("  Ready for next test run.")
    print("=" * 50)

if __name__ == "__main__":
    reset_canary_files()