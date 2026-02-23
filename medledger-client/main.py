"""
main.py - MedLedger Desktop Client entry point.

Run:  python main.py
Build: pyinstaller --onefile --windowed --name MedLedger main.py
"""

import sys
import os

# ── Make sure imports work whether run directly or as PyInstaller bundle ──────
if getattr(sys, "frozen", False):
    # Running as compiled bundle — sys._MEIPASS is the temp extraction dir
    bundle_dir = sys._MEIPASS
else:
    bundle_dir = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, bundle_dir)

# ── Now safe to import project modules ───────────────────────────────────────
from core.orchestrator import Orchestrator
from ui.app import App


def main():
    orch = Orchestrator()
    app  = App(orch)
    app.mainloop()


if __name__ == "__main__":
    main()
