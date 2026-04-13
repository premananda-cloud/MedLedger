#!/usr/bin/env python3
"""
MedLedger Desktop GUI
A modern PyQt6 dashboard for the MedLedger patient-controlled health vault.

Usage:
    python medledger_gui.py [--base-url http://localhost:8000]
"""

from __future__ import annotations
import sys, os, json, argparse, getpass, threading
from pathlib import Path
from datetime import datetime

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QLineEdit, QStackedWidget, QFrame,
        QScrollArea, QFileDialog, QComboBox, QSpinBox, QDoubleSpinBox,
        QTextEdit, QSizePolicy, QGraphicsDropShadowEffect, QMessageBox,
        QProgressBar, QToolButton, QCheckBox,
    )
    from PyQt6.QtCore import (
        Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve,
        QSize, QTimer, QPoint, pyqtProperty, QRect,
    )
    from PyQt6.QtGui import (
        QFont, QFontDatabase, QColor, QPainter, QPen, QBrush,
        QLinearGradient, QPalette, QIcon, QPixmap, QCursor,
        QPainterPath, QRadialGradient,
    )
except ImportError:
    sys.exit("PyQt6 not installed. Run: pip install PyQt6")

try:
    import requests
except ImportError:
    sys.exit("requests not installed. Run: pip install requests")

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_BASE = os.environ.get("MEDLEDGER_URL", "http://localhost:8000")
KEY_DIR = Path(".env")

# ── Palette ───────────────────────────────────────────────────────────────────
C = {
    "bg":        "#0D1117",
    "surface":   "#161B22",
    "surface2":  "#1C2430",
    "border":    "#21262D",
    "border2":   "#30363D",
    "accent":    "#2EA043",
    "accent2":   "#3FB950",
    "blue":      "#58A6FF",
    "purple":    "#BC8CFF",
    "orange":    "#F0883E",
    "red":       "#FF7B72",
    "yellow":    "#E3B341",
    "text":      "#E6EDF3",
    "text2":     "#8B949E",
    "text3":     "#484F58",
    "success":   "#2EA043",
    "warning":   "#9E6A03",
    "error":     "#DA3633",
    "grad1":     "#0D1117",
    "grad2":     "#0A3622",
}

QSS = f"""
QMainWindow, QDialog {{
    background: {C['bg']};
}}
QWidget {{
    background: transparent;
    color: {C['text']};
    font-family: 'Segoe UI', 'SF Pro Display', -apple-system, sans-serif;
    font-size: 13px;
}}
QScrollArea {{
    border: none;
    background: transparent;
}}
QScrollBar:vertical {{
    background: {C['bg']};
    width: 6px;
    border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: {C['border2']};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}
QLineEdit {{
    background: {C['surface2']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    padding: 10px 14px;
    color: {C['text']};
    font-size: 13px;
    selection-background-color: {C['accent']};
}}
QLineEdit:focus {{
    border: 1px solid {C['accent']};
    background: {C['surface']};
}}
QLineEdit::placeholder {{
    color: {C['text3']};
}}
QPushButton {{
    background: {C['surface2']};
    border: 1px solid {C['border2']};
    border-radius: 8px;
    padding: 10px 20px;
    color: {C['text']};
    font-size: 13px;
    font-weight: 500;
}}
QPushButton:hover {{
    background: {C['border']};
    border-color: {C['border2']};
}}
QPushButton:pressed {{
    background: {C['bg']};
}}
QPushButton.primary {{
    background: {C['accent']};
    border: none;
    color: white;
    font-weight: 600;
}}
QPushButton.primary:hover {{
    background: {C['accent2']};
}}
QPushButton.danger {{
    background: {C['error']};
    border: none;
    color: white;
    font-weight: 600;
}}
QPushButton.danger:hover {{
    background: #ff5c57;
}}
QComboBox {{
    background: {C['surface2']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    padding: 10px 14px;
    color: {C['text']};
    font-size: 13px;
}}
QComboBox:focus {{
    border-color: {C['accent']};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background: {C['surface']};
    border: 1px solid {C['border2']};
    color: {C['text']};
    selection-background-color: {C['accent']};
    padding: 4px;
}}
QTextEdit {{
    background: {C['surface2']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    padding: 10px 14px;
    color: {C['text']};
    font-family: 'Cascadia Code', 'JetBrains Mono', 'Consolas', monospace;
    font-size: 12px;
}}
QDoubleSpinBox, QSpinBox {{
    background: {C['surface2']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    padding: 10px 14px;
    color: {C['text']};
    font-size: 13px;
}}
QDoubleSpinBox:focus, QSpinBox:focus {{
    border-color: {C['accent']};
}}
QCheckBox {{
    color: {C['text2']};
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1px solid {C['border2']};
    background: {C['surface2']};
}}
QCheckBox::indicator:checked {{
    background: {C['accent']};
    border-color: {C['accent']};
}}
QToolTip {{
    background: {C['surface']};
    border: 1px solid {C['border2']};
    color: {C['text']};
    padding: 6px 10px;
    border-radius: 6px;
}}
"""

# ── HTTP helpers ───────────────────────────────────────────────────────────────
def _post(base, path, body, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.post(f"{base}{path}", json=body, headers=headers, timeout=30)
    if r.ok:
        return r.json(), None
    try:
        detail = r.json().get("detail", r.text)
    except Exception:
        detail = r.text
    return None, f"HTTP {r.status_code}: {detail}"

def _get(base, path, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.get(f"{base}{path}", headers=headers, timeout=30)
    if r.ok:
        return r.json(), None
    try:
        detail = r.json().get("detail", r.text)
    except Exception:
        detail = r.text
    return None, f"HTTP {r.status_code}: {detail}"

def key_path(username):
    return KEY_DIR / f"{username}.pem"

def save_key(username, pem):
    KEY_DIR.mkdir(exist_ok=True)
    p = key_path(username)
    p.write_text(pem)
    p.chmod(0o600)

def load_key(username):
    p = key_path(username)
    return p.read_text().strip() if p.exists() else None

# ── Worker thread ──────────────────────────────────────────────────────────────
class ApiWorker(QThread):
    done = pyqtSignal(object, object)   # (result, error)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.done.emit(result, None)
        except Exception as e:
            self.done.emit(None, str(e))

# ── Reusable widgets ───────────────────────────────────────────────────────────

class Card(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setStyleSheet(f"""
            #Card {{
                background: {C['surface']};
                border: 1px solid {C['border']};
                border-radius: 12px;
            }}
        """)

class StatCard(Card):
    def __init__(self, label, value, icon, color, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(8)

        top = QHBoxLayout()
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"font-size: 22px; color: {color};")
        top.addWidget(icon_lbl)
        top.addStretch()
        layout.addLayout(top)

        self.val_lbl = QLabel(str(value))
        self.val_lbl.setStyleSheet(f"font-size: 28px; font-weight: 700; color: {C['text']};")
        layout.addWidget(self.val_lbl)

        lbl = QLabel(label)
        lbl.setStyleSheet(f"font-size: 12px; color: {C['text2']};")
        layout.addWidget(lbl)

    def set_value(self, v):
        self.val_lbl.setText(str(v))

class SectionHeader(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(f"""
            font-size: 18px;
            font-weight: 700;
            color: {C['text']};
            padding-bottom: 4px;
        """)

class SubLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(f"font-size: 12px; color: {C['text2']};")

class Divider(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.HLine)
        self.setStyleSheet(f"color: {C['border']}; background: {C['border']};")
        self.setFixedHeight(1)

class StatusBadge(QLabel):
    STYLES = {
        "active":   (C['success'], "#0D2818"),
        "expired":  (C['orange'],  "#2D1A00"),
        "revoked":  (C['red'],     "#2D0A09"),
        "unknown":  (C['text2'],   C['surface2']),
    }
    def __init__(self, status="active", parent=None):
        super().__init__(parent)
        self.set_status(status)

    def set_status(self, status):
        color, bg = self.STYLES.get(status.lower(), self.STYLES["unknown"])
        self.setText(status.upper())
        self.setStyleSheet(f"""
            background: {bg};
            color: {color};
            border: 1px solid {color};
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.5px;
        """)
        self.setFixedHeight(22)

class NavButton(QPushButton):
    def __init__(self, icon, label, parent=None):
        super().__init__(parent)
        self.setText(f"  {icon}  {label}")
        self.setCheckable(True)
        self.setFixedHeight(42)
        self.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: none;
                border-radius: 8px;
                color: {C['text2']};
                font-size: 13px;
                font-weight: 500;
                text-align: left;
                padding: 0 12px;
            }}
            QPushButton:hover {{
                background: {C['surface2']};
                color: {C['text']};
            }}
            QPushButton:checked {{
                background: {C['surface2']};
                color: {C['accent2']};
                border-left: 2px solid {C['accent']};
            }}
        """)

class PasswordField(QLineEdit):
    def __init__(self, placeholder="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        self.setEchoMode(QLineEdit.EchoMode.Password)
        self._visible = False
        self._toggle = QToolButton(self)
        self._toggle.setText("👁")
        self._toggle.setStyleSheet("background: transparent; border: none; color: #8B949E; font-size: 14px;")
        self._toggle.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self._toggle.clicked.connect(self._toggle_visibility)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._toggle.move(self.width() - 32, (self.height() - 20) // 2)

    def _toggle_visibility(self):
        self._visible = not self._visible
        self.setEchoMode(QLineEdit.EchoMode.Normal if self._visible else QLineEdit.EchoMode.Password)

class Toast(QFrame):
    def __init__(self, msg, kind="info", parent=None):
        super().__init__(parent)
        colors = {"success": C['success'], "error": C['red'], "info": C['blue'], "warn": C['orange']}
        icons  = {"success": "✓", "error": "✕", "info": "ℹ", "warn": "⚠"}
        color  = colors.get(kind, C['blue'])
        icon   = icons.get(kind, "ℹ")

        self.setFixedHeight(48)
        self.setMinimumWidth(300)
        self.setStyleSheet(f"""
            QFrame {{
                background: {C['surface']};
                border: 1px solid {color};
                border-left: 3px solid {color};
                border-radius: 8px;
            }}
        """)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 0, 14, 0)
        layout.setSpacing(10)
        i = QLabel(icon)
        i.setStyleSheet(f"color: {color}; font-size: 16px; border: none;")
        layout.addWidget(i)
        m = QLabel(msg)
        m.setStyleSheet(f"color: {C['text']}; font-size: 13px; border: none;")
        m.setWordWrap(True)
        layout.addWidget(m, 1)

class RecordRow(Card):
    download_clicked = pyqtSignal(str, str)
    grant_clicked    = pyqtSignal(str, str)

    def __init__(self, record, parent=None):
        super().__init__(parent)
        self.record_id = record["record_id"]
        self.filename  = record["filename"]
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        ext = Path(record["filename"]).suffix.lower()
        ext_icons = {".pdf": "📄", ".jpg": "🖼", ".jpeg": "🖼", ".png": "🖼",
                     ".txt": "📝", ".csv": "📊", ".doc": "📋", ".docx": "📋",
                     ".xml": "🗂", ".json": "🗂"}
        icon_lbl = QLabel(ext_icons.get(ext, "📁"))
        icon_lbl.setStyleSheet("font-size: 24px;")
        icon_lbl.setFixedWidth(36)
        layout.addWidget(icon_lbl)

        meta = QVBoxLayout()
        meta.setSpacing(2)
        fname = QLabel(record["filename"])
        fname.setStyleSheet(f"font-size: 13px; font-weight: 600; color: {C['text']};")
        meta.addWidget(fname)

        size_kb = record.get("size_bytes", 0) / 1024
        ts_raw  = record.get("created_at", "")
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).strftime("%b %d, %Y · %H:%M")
        except Exception:
            ts = ts_raw[:19] if ts_raw else "—"
        tags = record.get("tags", [])
        tag_str = "  ·  " + "  ".join(f"#{t}" for t in tags) if tags else ""
        sub = QLabel(f"{size_kb:.1f} KB  ·  {ts}{tag_str}")
        sub.setStyleSheet(f"font-size: 11px; color: {C['text2']};")
        meta.addWidget(sub)
        layout.addLayout(meta, 1)

        rid_short = QLabel(record["record_id"][:8] + "…")
        rid_short.setStyleSheet(f"font-family: monospace; font-size: 10px; color: {C['text3']};")
        rid_short.setToolTip(record["record_id"])
        layout.addWidget(rid_short)

        dl_btn = QPushButton("⬇  Download")
        dl_btn.setProperty("class", "primary")
        dl_btn.setFixedHeight(34)
        dl_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['accent']};
                border: none; border-radius: 7px;
                color: white; font-size: 12px; font-weight: 600;
                padding: 0 14px;
            }}
            QPushButton:hover {{ background: {C['accent2']}; }}
        """)
        dl_btn.clicked.connect(lambda: self.download_clicked.emit(self.record_id, self.filename))
        layout.addWidget(dl_btn)

        gr_btn = QPushButton("🔑  Grant")
        gr_btn.setFixedHeight(34)
        gr_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['surface2']};
                border: 1px solid {C['border2']};
                border-radius: 7px;
                color: {C['text2']}; font-size: 12px;
                padding: 0 14px;
            }}
            QPushButton:hover {{ color: {C['text']}; border-color: {C['blue']}; }}
        """)
        gr_btn.clicked.connect(lambda: self.grant_clicked.emit(self.record_id, self.filename))
        layout.addWidget(gr_btn)

class GrantRow(Card):
    revoke_clicked = pyqtSignal(str)

    def __init__(self, grant, show_revoke=True, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        status = "revoked" if grant.get("revoked") else ("active" if grant.get("time_valid") else "expired")
        badge = StatusBadge(status)
        layout.addWidget(badge)

        meta = QVBoxLayout()
        meta.setSpacing(3)
        gid = QLabel(grant.get("grant_id", "")[:16] + "…")
        gid.setStyleSheet(f"font-family: monospace; font-size: 12px; color: {C['text']};")
        gid.setToolTip(grant.get("grant_id", ""))
        meta.addWidget(gid)

        fname = grant.get("filename", "—")
        perm  = grant.get("permission_level", "—")
        sig   = "✓ sig ok" if grant.get("signature_valid") else "✕ sig bad"
        sub = QLabel(f"📄 {fname}  ·  {perm}  ·  {sig}")
        sub.setStyleSheet(f"font-size: 11px; color: {C['text2']};")
        meta.addWidget(sub)
        layout.addLayout(meta, 1)

        exp_raw = grant.get("time_end", "")
        try:
            exp = datetime.fromisoformat(exp_raw.replace("Z", "+00:00")).strftime("%b %d, %Y %H:%M")
        except Exception:
            exp = exp_raw[:16] if exp_raw else "—"
        exp_lbl = QLabel(f"Expires\n{exp}")
        exp_lbl.setStyleSheet(f"font-size: 11px; color: {C['text2']}; text-align: right;")
        exp_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(exp_lbl)

        if show_revoke and status == "active":
            rev_btn = QPushButton("Revoke")
            rev_btn.setFixedHeight(30)
            grant_id = grant.get("grant_id", "")
            rev_btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    border: 1px solid {C['red']};
                    border-radius: 6px;
                    color: {C['red']};
                    font-size: 11px; padding: 0 10px;
                }}
                QPushButton:hover {{ background: {C['error']}20; }}
            """)
            rev_btn.clicked.connect(lambda: self.revoke_clicked.emit(grant_id))
            layout.addWidget(rev_btn)

# ── Pages ──────────────────────────────────────────────────────────────────────

class LoginPage(QWidget):
    login_success = pyqtSignal(str, str, dict)   # token, username, profile
    switch_register = pyqtSignal()

    def __init__(self, base_url, parent=None):
        super().__init__(parent)
        self.base_url = base_url
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        outer.setContentsMargins(0, 0, 0, 0)

        container = QWidget()
        container.setFixedWidth(420)
        layout = QVBoxLayout(container)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        # Logo block
        logo_box = QWidget()
        logo_box.setStyleSheet(f"background: {C['surface']}; border-radius: 16px 16px 0 0; border: 1px solid {C['border']};")
        logo_layout = QVBoxLayout(logo_box)
        logo_layout.setContentsMargins(40, 36, 40, 28)
        logo_layout.setSpacing(4)

        logo = QLabel("🏥 MedLedger")
        logo.setStyleSheet(f"font-size: 26px; font-weight: 800; color: {C['text']}; letter-spacing: -0.5px;")
        logo_layout.addWidget(logo)
        sub  = QLabel("Patient-Controlled Health Vault")
        sub.setStyleSheet(f"font-size: 13px; color: {C['text2']};")
        logo_layout.addWidget(sub)
        layout.addWidget(logo_box)

        # Form card
        form_card = QWidget()
        form_card.setStyleSheet(f"background: {C['surface2']}; border-radius: 0 0 16px 16px; border: 1px solid {C['border']}; border-top: none;")
        form_layout = QVBoxLayout(form_card)
        form_layout.setContentsMargins(40, 32, 40, 36)
        form_layout.setSpacing(14)

        hdr = QLabel("Sign in to your account")
        hdr.setStyleSheet(f"font-size: 16px; font-weight: 600; color: {C['text']};")
        form_layout.addWidget(hdr)
        form_layout.addSpacing(4)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email address")
        self.email_input.setFixedHeight(44)
        form_layout.addWidget(self.email_input)

        self.pw_input = PasswordField("Password")
        self.pw_input.setFixedHeight(44)
        form_layout.addWidget(self.pw_input)

        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        self.status_lbl.setFixedHeight(22)
        self.status_lbl.setStyleSheet(f"font-size: 12px; color: {C['red']};")
        form_layout.addWidget(self.status_lbl)

        self.login_btn = QPushButton("Sign In")
        self.login_btn.setFixedHeight(44)
        self.login_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['accent']};
                border: none; border-radius: 8px;
                color: white; font-size: 14px; font-weight: 600;
            }}
            QPushButton:hover {{ background: {C['accent2']}; }}
            QPushButton:disabled {{ background: {C['border2']}; color: {C['text3']}; }}
        """)
        self.login_btn.clicked.connect(self._do_login)
        self.email_input.returnPressed.connect(self._do_login)
        self.pw_input.returnPressed.connect(self._do_login)
        form_layout.addWidget(self.login_btn)

        form_layout.addSpacing(8)
        sep_layout = QHBoxLayout()
        sep_layout.addWidget(Divider())
        or_lbl = QLabel("  or  ")
        or_lbl.setStyleSheet(f"color: {C['text3']}; font-size: 12px;")
        sep_layout.addWidget(or_lbl)
        sep_layout.addWidget(Divider())
        form_layout.addLayout(sep_layout)
        form_layout.addSpacing(8)

        reg_btn = QPushButton("Create new account")
        reg_btn.setFixedHeight(42)
        reg_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                border: 1px solid {C['border2']};
                border-radius: 8px;
                color: {C['text2']}; font-size: 13px;
            }}
            QPushButton:hover {{ color: {C['text']}; border-color: {C['text2']}; }}
        """)
        reg_btn.clicked.connect(self.switch_register.emit)
        form_layout.addWidget(reg_btn)

        layout.addWidget(form_card)
        outer.addWidget(container)

    def _do_login(self):
        email = self.email_input.text().strip()
        pw    = self.pw_input.text()
        if not email or not pw:
            self.status_lbl.setText("Please fill in all fields.")
            return
        self.login_btn.setEnabled(False)
        self.login_btn.setText("Signing in…")
        self.status_lbl.setText("")

        def _work():
            return _post(self.base_url, "/api/auth/login", {"email": email, "password": pw})

        self._worker = ApiWorker(_work)
        self._worker.done.connect(self._on_login_done)
        self._worker.start()

    def _on_login_done(self, result, err):
        self.login_btn.setEnabled(True)
        self.login_btn.setText("Sign In")
        if err or result is None:
            resp, api_err = result if (result and isinstance(result, tuple)) else (None, err or "Unknown error")
            self.status_lbl.setText(str(api_err or err))
            return
        resp, api_err = result
        if api_err:
            self.status_lbl.setText(api_err)
            return
        self.login_success.emit(resp["access_token"], resp["username"], resp)


class RegisterPage(QWidget):
    register_success = pyqtSignal(str)
    switch_login = pyqtSignal()

    def __init__(self, base_url, parent=None):
        super().__init__(parent)
        self.base_url = base_url
        self._build()

    def _build(self):
        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(scroll)

        container = QWidget()
        container.setFixedWidth(440)
        main_layout = QVBoxLayout(container)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        main_layout.setContentsMargins(0, 40, 0, 40)
        main_layout.setSpacing(0)
        scroll.setWidget(container)

        card = Card()
        cl = QVBoxLayout(card)
        cl.setContentsMargins(40, 36, 40, 36)
        cl.setSpacing(14)

        logo = QLabel("🏥 MedLedger  ·  Create Account")
        logo.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {C['text']};")
        cl.addWidget(logo)
        cl.addWidget(SubLabel("Secure, patient-controlled health data vault"))
        cl.addSpacing(8)

        def field(ph, pw=False):
            w = PasswordField(ph) if pw else QLineEdit()
            if not pw:
                w.setPlaceholderText(ph)
            w.setFixedHeight(44)
            return w

        self.email_i    = field("Email address")
        self.user_i     = field("Username")
        self.name_i     = field("Full name (optional)")
        self.pw_i       = field("Password (min 8 chars)", pw=True)
        self.pw2_i      = field("Confirm password", pw=True)

        for w in [self.email_i, self.user_i, self.name_i, self.pw_i, self.pw2_i]:
            cl.addWidget(w)

        self.role_combo = QComboBox()
        self.role_combo.addItems(["PATIENT", "DOCTOR"])
        self.role_combo.setFixedHeight(44)
        cl.addWidget(self.role_combo)

        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        self.status_lbl.setStyleSheet(f"font-size: 12px; color: {C['red']};")
        cl.addWidget(self.status_lbl)

        self.reg_btn = QPushButton("Create Account")
        self.reg_btn.setFixedHeight(44)
        self.reg_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['accent']};
                border: none; border-radius: 8px;
                color: white; font-size: 14px; font-weight: 600;
            }}
            QPushButton:hover {{ background: {C['accent2']}; }}
            QPushButton:disabled {{ background: {C['border2']}; color: {C['text3']}; }}
        """)
        self.reg_btn.clicked.connect(self._do_register)
        cl.addWidget(self.reg_btn)

        back_btn = QPushButton("← Back to sign in")
        back_btn.setStyleSheet(f"background: transparent; border: none; color: {C['text2']}; font-size: 13px;")
        back_btn.clicked.connect(self.switch_login.emit)
        cl.addWidget(back_btn)

        main_layout.addWidget(card)

    def _do_register(self):
        email = self.email_i.text().strip()
        user  = self.user_i.text().strip()
        name  = self.name_i.text().strip()
        pw    = self.pw_i.text()
        pw2   = self.pw2_i.text()
        role  = self.role_combo.currentText()

        if not email or not user or not pw:
            self.status_lbl.setText("Email, username and password are required.")
            return
        if len(pw) < 8:
            self.status_lbl.setText("Password must be at least 8 characters.")
            return
        if pw != pw2:
            self.status_lbl.setText("Passwords do not match.")
            return

        self.reg_btn.setEnabled(False)
        self.reg_btn.setText("Creating account…")
        self.status_lbl.setText("")

        def _work():
            res, err = _post(self.base_url, "/api/auth/register", {
                "email": email, "password": pw,
                "username": user, "full_name": name, "role": role,
            })
            if err:
                return None, err
            token = res.get("verification_token")
            if not token:
                return None, "Server did not return a verification token."
            vres, verr = _post(self.base_url, "/api/auth/verify", {"token": token})
            if verr:
                return None, verr
            pem = vres.get("private_key_pem")
            if not pem:
                return None, "Server did not return private key."
            save_key(user, pem)
            return user, None

        self._worker = ApiWorker(_work)
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _on_done(self, result, err):
        self.reg_btn.setEnabled(True)
        self.reg_btn.setText("Create Account")
        if err:
            self.status_lbl.setText(str(err))
            return
        username, api_err = result
        if api_err:
            self.status_lbl.setText(api_err)
            return
        self.register_success.emit(username)


# ── Dashboard ──────────────────────────────────────────────────────────────────

class DashboardPage(QWidget):
    logout_requested = pyqtSignal()

    def __init__(self, base_url, token, username, profile, parent=None):
        super().__init__(parent)
        self.base_url  = base_url
        self.token     = token
        self.username  = username
        self.profile   = profile
        self._workers  = []
        self._build()
        self._load_overview()

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Sidebar ──────────────────────────────────────────────────────────
        sidebar = QWidget()
        sidebar.setFixedWidth(220)
        sidebar.setStyleSheet(f"background: {C['surface']}; border-right: 1px solid {C['border']};")
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(12, 20, 12, 16)
        sb_layout.setSpacing(4)

        logo_lbl = QLabel("🏥 MedLedger")
        logo_lbl.setStyleSheet(f"font-size: 16px; font-weight: 800; color: {C['text']}; padding: 0 8px 4px 8px;")
        sb_layout.addWidget(logo_lbl)

        ver_lbl = QLabel("Health Vault v2")
        ver_lbl.setStyleSheet(f"font-size: 10px; color: {C['text3']}; padding: 0 8px 16px 8px;")
        sb_layout.addWidget(ver_lbl)
        sb_layout.addWidget(Divider())
        sb_layout.addSpacing(8)

        nav_items = [
            ("📊", "Overview",  0),
            ("📁", "My Records", 1),
            ("📤", "Upload",    2),
            ("🔑", "Access",    3),
            ("📬", "Inbox",     4),
            ("👤", "Profile",   5),
        ]
        self._nav_btns = []
        for icon, label, idx in nav_items:
            btn = NavButton(icon, label)
            btn.clicked.connect(lambda checked, i=idx: self._switch_page(i))
            sb_layout.addWidget(btn)
            self._nav_btns.append(btn)

        sb_layout.addStretch()
        sb_layout.addWidget(Divider())
        sb_layout.addSpacing(8)

        # User chip
        user_chip = QWidget()
        chip_layout = QHBoxLayout(user_chip)
        chip_layout.setContentsMargins(8, 6, 8, 6)
        chip_layout.setSpacing(10)
        avatar = QLabel("👤")
        avatar.setStyleSheet(f"font-size: 18px;")
        chip_layout.addWidget(avatar)
        name_col = QVBoxLayout()
        name_col.setSpacing(0)
        uname = QLabel(self.username)
        uname.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {C['text']};")
        name_col.addWidget(uname)
        role = QLabel(self.profile.get("role", "PATIENT"))
        role.setStyleSheet(f"font-size: 10px; color: {C['text2']};")
        name_col.addWidget(role)
        chip_layout.addLayout(name_col, 1)

        logout_btn = QToolButton()
        logout_btn.setText("⏻")
        logout_btn.setToolTip("Logout")
        logout_btn.setStyleSheet(f"background: transparent; border: none; color: {C['text3']}; font-size: 14px;")
        logout_btn.clicked.connect(self.logout_requested.emit)
        chip_layout.addWidget(logout_btn)
        sb_layout.addWidget(user_chip)

        root.addWidget(sidebar)

        # ── Content area ──────────────────────────────────────────────────────
        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"background: {C['bg']};")

        self._stack.addWidget(self._build_overview())
        self._stack.addWidget(self._build_records())
        self._stack.addWidget(self._build_upload())
        self._stack.addWidget(self._build_access())
        self._stack.addWidget(self._build_inbox())
        self._stack.addWidget(self._build_profile())

        root.addWidget(self._stack, 1)
        self._nav_btns[0].setChecked(True)

    def _switch_page(self, idx):
        self._stack.setCurrentIndex(idx)
        for i, btn in enumerate(self._nav_btns):
            btn.setChecked(i == idx)
        if idx == 0: self._load_overview()
        if idx == 1: self._load_records()
        if idx == 3: self._load_access()
        if idx == 4: self._load_inbox()
        if idx == 5: self._load_profile()

    def _scrollable(self, inner):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(inner)
        return scroll

    def _page_layout(self, title, subtitle=""):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(20)

        hdr = SectionHeader(title)
        layout.addWidget(hdr)
        if subtitle:
            layout.addWidget(SubLabel(subtitle))
            layout.addSpacing(-8)
        return page, layout

    # ── Overview ──────────────────────────────────────────────────────────────
    def _build_overview(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(24)

        welcome = SectionHeader(f"Welcome back, {self.username} 👋")
        layout.addWidget(welcome)
        layout.addWidget(SubLabel("Here's your vault at a glance."))

        stats_row = QHBoxLayout()
        stats_row.setSpacing(16)
        self._stat_records  = StatCard("Total Records",       "–", "📁", C['blue'])
        self._stat_grants   = StatCard("Active Grants",       "–", "🔑", C['accent'])
        self._stat_inbox    = StatCard("Shared With You",     "–", "📬", C['purple'])
        self._stat_size     = StatCard("Vault Size",          "–", "💾", C['orange'])
        for c in [self._stat_records, self._stat_grants, self._stat_inbox, self._stat_size]:
            stats_row.addWidget(c)
        layout.addLayout(stats_row)

        layout.addWidget(SectionHeader("Recent Records"))
        self._overview_records_layout = QVBoxLayout()
        self._overview_records_layout.setSpacing(8)
        layout.addLayout(self._overview_records_layout)

        layout.addStretch()
        outer.addWidget(self._scrollable(inner))
        return page

    def _load_overview(self):
        def _work():
            records, rerr = _get(self.base_url, "/api/vault/records", self.token)
            pem = load_key(self.username)
            grants, gerr = (None, "no key") if not pem else _post(
                self.base_url, "/api/vault/permissions", {"private_key_pem": pem}, self.token)
            inbox, ierr = (None, "no key") if not pem else _post(
                self.base_url, "/api/vault/inbox", {"private_key_pem": pem}, self.token)
            return records, grants, inbox

        w = ApiWorker(_work)
        w.done.connect(self._on_overview_done)
        w.start()
        self._workers.append(w)

    def _on_overview_done(self, result, err):
        if err or not result:
            return
        records, grants, inbox = result
        records = records or []
        grants  = [g for g in (grants or []) if not g.get("revoked") and g.get("time_valid")]
        inbox   = [g for g in (inbox or [])  if not g.get("revoked") and g.get("time_valid")]

        self._stat_records.set_value(len(records))
        self._stat_grants.set_value(len(grants))
        self._stat_inbox.set_value(len(inbox))
        total_bytes = sum(r.get("size_bytes", 0) for r in records)
        if total_bytes < 1024:
            sz = f"{total_bytes} B"
        elif total_bytes < 1024**2:
            sz = f"{total_bytes/1024:.1f} KB"
        else:
            sz = f"{total_bytes/1024**2:.1f} MB"
        self._stat_size.set_value(sz)

        # Clear and repopulate recent 3
        for i in reversed(range(self._overview_records_layout.count())):
            self._overview_records_layout.itemAt(i).widget().deleteLater()

        for r in records[:3]:
            row = RecordRow(r)
            row.download_clicked.connect(self._download_record)
            row.grant_clicked.connect(self._open_grant_dialog)
            self._overview_records_layout.addWidget(row)

        if not records:
            lbl = QLabel("No records yet. Upload your first file from the Upload tab.")
            lbl.setStyleSheet(f"color: {C['text2']}; font-size: 13px; padding: 20px; text-align: center;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._overview_records_layout.addWidget(lbl)

    # ── Records ───────────────────────────────────────────────────────────────
    def _build_records(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)

        hdr_row = QHBoxLayout()
        hdr_row.addWidget(SectionHeader("My Records"))
        hdr_row.addStretch()
        refresh_btn = QPushButton("⟳  Refresh")
        refresh_btn.setFixedHeight(34)
        refresh_btn.clicked.connect(self._load_records)
        hdr_row.addWidget(refresh_btn)
        layout.addLayout(hdr_row)
        layout.addWidget(SubLabel("All encrypted files in your personal health vault."))

        self._records_layout = QVBoxLayout()
        self._records_layout.setSpacing(8)
        self._records_placeholder = QLabel("Loading records…")
        self._records_placeholder.setStyleSheet(f"color: {C['text2']}; padding: 24px;")
        self._records_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._records_layout.addWidget(self._records_placeholder)
        layout.addLayout(self._records_layout)
        layout.addStretch()

        outer.addWidget(self._scrollable(inner))
        return page

    def _load_records(self):
        self._records_placeholder.setText("Loading records…")
        self._records_placeholder.show()

        def _work():
            return _get(self.base_url, "/api/vault/records", self.token)

        w = ApiWorker(_work)
        w.done.connect(self._on_records_done)
        w.start()
        self._workers.append(w)

    def _on_records_done(self, result, err):
        # Clear existing rows (except placeholder)
        for i in reversed(range(self._records_layout.count())):
            item = self._records_layout.itemAt(i)
            if item and item.widget() and item.widget() != self._records_placeholder:
                item.widget().deleteLater()

        if err:
            self._records_placeholder.setText(f"Error: {err}")
            return

        records, api_err = result
        if api_err:
            self._records_placeholder.setText(f"Error: {api_err}")
            return
        if not records:
            self._records_placeholder.setText("No records in your vault. Upload a file to get started.")
            return

        self._records_placeholder.hide()
        for r in records:
            row = RecordRow(r)
            row.download_clicked.connect(self._download_record)
            row.grant_clicked.connect(self._open_grant_dialog)
            self._records_layout.addWidget(row)

    # ── Upload ────────────────────────────────────────────────────────────────
    def _build_upload(self):
        page, layout = self._page_layout("Upload File", "Encrypt and store a file in your vault.")
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        card = Card()
        cl = QVBoxLayout(card)
        cl.setContentsMargins(28, 24, 28, 24)
        cl.setSpacing(16)

        # Drop zone
        drop_zone = QFrame()
        drop_zone.setFixedHeight(120)
        drop_zone.setStyleSheet(f"""
            QFrame {{
                background: {C['bg']};
                border: 2px dashed {C['border2']};
                border-radius: 10px;
            }}
        """)
        dz_layout = QVBoxLayout(drop_zone)
        dz_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._upload_fname_lbl = QLabel("📂  Click to select a file")
        self._upload_fname_lbl.setStyleSheet(f"font-size: 14px; color: {C['text2']};")
        self._upload_fname_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dz_layout.addWidget(self._upload_fname_lbl)
        self._upload_fsize_lbl = QLabel("")
        self._upload_fsize_lbl.setStyleSheet(f"font-size: 11px; color: {C['text3']};")
        self._upload_fsize_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dz_layout.addWidget(self._upload_fsize_lbl)
        cl.addWidget(drop_zone)

        self._upload_filepath = None
        browse_btn = QPushButton("Browse Files")
        browse_btn.setFixedHeight(38)
        browse_btn.clicked.connect(self._browse_file)
        cl.addWidget(browse_btn)

        cl.addWidget(SubLabel("Tags (comma-separated, optional)"))
        self._upload_tags = QLineEdit()
        self._upload_tags.setPlaceholderText("e.g. blood-test, 2024, cardiology")
        self._upload_tags.setFixedHeight(40)
        cl.addWidget(self._upload_tags)

        self._upload_status = QLabel("")
        self._upload_status.setWordWrap(True)
        self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['text2']};")
        cl.addWidget(self._upload_status)

        self._upload_btn = QPushButton("🔒  Encrypt & Upload")
        self._upload_btn.setFixedHeight(44)
        self._upload_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['accent']};
                border: none; border-radius: 8px;
                color: white; font-size: 14px; font-weight: 600;
            }}
            QPushButton:hover {{ background: {C['accent2']}; }}
            QPushButton:disabled {{ background: {C['border2']}; color: {C['text3']}; }}
        """)
        self._upload_btn.clicked.connect(self._do_upload)
        cl.addWidget(self._upload_btn)

        layout.addWidget(card)
        layout.addStretch()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(page)
        return scroll

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file to upload")
        if path:
            self._upload_filepath = path
            fname = Path(path).name
            size  = Path(path).stat().st_size
            size_str = f"{size/1024:.1f} KB" if size < 1024**2 else f"{size/1024**2:.1f} MB"
            self._upload_fname_lbl.setText(f"📄  {fname}")
            self._upload_fname_lbl.setStyleSheet(f"font-size: 13px; color: {C['text']};")
            self._upload_fsize_lbl.setText(size_str)

    def _do_upload(self):
        if not self._upload_filepath:
            self._upload_status.setText("⚠ Please select a file first.")
            self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['orange']};")
            return
        pem = load_key(self.username)
        if not pem:
            self._upload_status.setText(f"✕ Private key not found at .env/{self.username}.pem")
            self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['red']};")
            return

        p    = Path(self._upload_filepath)
        raw  = p.read_bytes()
        tags = [t.strip() for t in self._upload_tags.text().split(",") if t.strip()]

        self._upload_btn.setEnabled(False)
        self._upload_btn.setText("Uploading…")
        self._upload_status.setText("Encrypting and uploading…")
        self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['text2']};")

        def _work():
            return _post(self.base_url, "/api/vault/upload", {
                "private_key_pem": pem,
                "filename":        p.name,
                "plaintext_hex":   raw.hex(),
                "tags":            tags,
            }, self.token)

        w = ApiWorker(_work)
        w.done.connect(self._on_upload_done)
        w.start()
        self._workers.append(w)

    def _on_upload_done(self, result, err):
        self._upload_btn.setEnabled(True)
        self._upload_btn.setText("🔒  Encrypt & Upload")
        if err:
            self._upload_status.setText(f"✕ {err}")
            self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['red']};")
            return
        resp, api_err = result
        if api_err:
            self._upload_status.setText(f"✕ {api_err}")
            self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['red']};")
            return
        self._upload_status.setText(
            f"✓  Uploaded '{resp['filename']}' — Record ID: {resp['record_id'][:16]}…")
        self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['success']};")
        self._upload_filepath = None
        self._upload_fname_lbl.setText("📂  Click to select a file")
        self._upload_fname_lbl.setStyleSheet(f"font-size: 14px; color: {C['text2']};")
        self._upload_fsize_lbl.setText("")
        self._upload_tags.clear()

    # ── Download helper ───────────────────────────────────────────────────────
    def _download_record(self, record_id, filename):
        pem = load_key(self.username)
        if not pem:
            QMessageBox.warning(self, "No Key", f"Private key not found at .env/{self.username}.pem")
            return
        out_path, _ = QFileDialog.getSaveFileName(self, "Save file as", filename)
        if not out_path:
            return

        def _work():
            return _post(self.base_url, f"/api/vault/download/{record_id}",
                         {"private_key_pem": pem}, self.token)

        def _on_done(result, err):
            if err:
                QMessageBox.critical(self, "Download failed", str(err))
                return
            resp, api_err = result
            if api_err:
                QMessageBox.critical(self, "Download failed", api_err)
                return
            raw = bytes.fromhex(resp["plaintext_hex"])
            Path(out_path).write_bytes(raw)
            QMessageBox.information(self, "Downloaded",
                f"Saved {resp['filename']} ({resp['size_bytes']} bytes)\n→ {out_path}")

        w = ApiWorker(_work)
        w.done.connect(_on_done)
        w.start()
        self._workers.append(w)

    # ── Grant dialog ──────────────────────────────────────────────────────────
    def _open_grant_dialog(self, record_id, filename):
        from PyQt6.QtWidgets import QDialog
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Grant Access — {filename}")
        dlg.setFixedWidth(500)
        dlg.setStyleSheet(f"background: {C['surface']}; color: {C['text']};")
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        layout.addWidget(SectionHeader("Grant Access"))
        layout.addWidget(SubLabel(f"Record: {filename}  ·  {record_id[:16]}…"))

        layout.addWidget(QLabel("Grantee Public Key (hex, 130 chars):"))
        pub_input = QLineEdit()
        pub_input.setPlaceholderText("04ab12ef…  (130-char uncompressed public key hex)")
        pub_input.setFixedHeight(40)
        layout.addWidget(pub_input)

        perm_combo = QComboBox()
        perm_combo.addItems(["view_only", "view_download"])
        perm_combo.setFixedHeight(40)
        layout.addWidget(QLabel("Permission Level:"))
        layout.addWidget(perm_combo)

        layout.addWidget(QLabel("Duration (hours):"))
        hours_spin = QDoubleSpinBox()
        hours_spin.setRange(0.5, 8760)
        hours_spin.setValue(24)
        hours_spin.setSuffix(" hours")
        hours_spin.setFixedHeight(40)
        layout.addWidget(hours_spin)

        status_lbl = QLabel("")
        status_lbl.setStyleSheet(f"font-size: 12px; color: {C['red']};")
        layout.addWidget(status_lbl)

        btn_row = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dlg.reject)
        grant_btn = QPushButton("Grant Access 🔑")
        grant_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['accent']}; border: none; border-radius: 8px;
                color: white; font-size: 13px; font-weight: 600; padding: 8px 20px;
            }}
            QPushButton:hover {{ background: {C['accent2']}; }}
        """)

        def _do():
            pem = load_key(self.username)
            if not pem:
                status_lbl.setText("Private key not found.")
                return
            grantee = pub_input.text().strip()
            if len(grantee) < 100:
                status_lbl.setText("Public key must be 130 hex characters.")
                return
            grant_btn.setEnabled(False)
            grant_btn.setText("Granting…")

            def _work():
                return _post(self.base_url, "/api/vault/grant", {
                    "private_key_pem":        pem,
                    "record_id":              record_id,
                    "grantee_public_key_hex": grantee,
                    "permission_level":       perm_combo.currentText(),
                    "duration_hours":         hours_spin.value(),
                }, self.token)

            def _on_done(result, err):
                grant_btn.setEnabled(True)
                grant_btn.setText("Grant Access 🔑")
                if err:
                    status_lbl.setText(str(err))
                    return
                resp, api_err = result
                if api_err:
                    status_lbl.setText(api_err)
                    return
                QMessageBox.information(self, "Grant Created",
                    f"Grant ID: {resp['grant_id']}\nExpires: {resp.get('time_end', '?')[:19]}")
                dlg.accept()

            w = ApiWorker(_work)
            w.done.connect(_on_done)
            w.start()
            self._workers.append(w)

        grant_btn.clicked.connect(_do)
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(grant_btn)
        layout.addLayout(btn_row)
        dlg.exec()

    # ── Access (outbox) ───────────────────────────────────────────────────────
    def _build_access(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)

        hdr_row = QHBoxLayout()
        hdr_row.addWidget(SectionHeader("Access Grants (Outbox)"))
        hdr_row.addStretch()
        refresh_btn = QPushButton("⟳  Refresh")
        refresh_btn.setFixedHeight(34)
        refresh_btn.clicked.connect(self._load_access)
        hdr_row.addWidget(refresh_btn)
        layout.addLayout(hdr_row)
        layout.addWidget(SubLabel("Permissions you have issued to other users."))

        self._access_layout = QVBoxLayout()
        self._access_layout.setSpacing(8)
        self._access_placeholder = QLabel("Loading…")
        self._access_placeholder.setStyleSheet(f"color: {C['text2']}; padding: 24px;")
        self._access_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._access_layout.addWidget(self._access_placeholder)
        layout.addLayout(self._access_layout)
        layout.addStretch()

        outer.addWidget(self._scrollable(inner))
        return page

    def _load_access(self):
        pem = load_key(self.username)
        if not pem:
            self._access_placeholder.setText("Private key not found.")
            return

        def _work():
            return _post(self.base_url, "/api/vault/permissions", {"private_key_pem": pem}, self.token)

        w = ApiWorker(_work)
        w.done.connect(self._on_access_done)
        w.start()
        self._workers.append(w)

    def _on_access_done(self, result, err):
        for i in reversed(range(self._access_layout.count())):
            item = self._access_layout.itemAt(i)
            if item and item.widget() and item.widget() != self._access_placeholder:
                item.widget().deleteLater()

        if err:
            self._access_placeholder.setText(f"Error: {err}")
            return
        grants, api_err = result
        if api_err:
            self._access_placeholder.setText(f"Error: {api_err}")
            return
        if not grants:
            self._access_placeholder.setText("No access grants issued yet.")
            return
        self._access_placeholder.hide()

        for g in grants:
            row = GrantRow(g, show_revoke=True)
            row.revoke_clicked.connect(self._do_revoke)
            self._access_layout.addWidget(row)

    def _do_revoke(self, grant_id):
        pem = load_key(self.username)
        if not pem:
            QMessageBox.warning(self, "No Key", "Private key not found.")
            return
        confirm = QMessageBox.question(self, "Revoke Grant",
            f"Revoke grant {grant_id[:16]}…?\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes:
            return

        def _work():
            return _post(self.base_url, "/api/vault/revoke",
                         {"private_key_pem": pem, "grant_id": grant_id}, self.token)

        def _on_done(result, err):
            if err:
                QMessageBox.critical(self, "Revoke failed", str(err))
            else:
                self._load_access()

        w = ApiWorker(_work)
        w.done.connect(_on_done)
        w.start()
        self._workers.append(w)

    # ── Inbox ─────────────────────────────────────────────────────────────────
    def _build_inbox(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)

        hdr_row = QHBoxLayout()
        hdr_row.addWidget(SectionHeader("Inbox"))
        hdr_row.addStretch()
        refresh_btn = QPushButton("⟳  Refresh")
        refresh_btn.setFixedHeight(34)
        refresh_btn.clicked.connect(self._load_inbox)
        hdr_row.addWidget(refresh_btn)
        layout.addLayout(hdr_row)
        layout.addWidget(SubLabel("Records shared with you by other users."))

        self._inbox_layout = QVBoxLayout()
        self._inbox_layout.setSpacing(8)
        self._inbox_placeholder = QLabel("Loading…")
        self._inbox_placeholder.setStyleSheet(f"color: {C['text2']}; padding: 24px;")
        self._inbox_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._inbox_layout.addWidget(self._inbox_placeholder)
        layout.addLayout(self._inbox_layout)
        layout.addStretch()

        outer.addWidget(self._scrollable(inner))
        return page

    def _load_inbox(self):
        pem = load_key(self.username)
        if not pem:
            self._inbox_placeholder.setText("Private key not found.")
            return

        def _work():
            return _post(self.base_url, "/api/vault/inbox", {"private_key_pem": pem}, self.token)

        w = ApiWorker(_work)
        w.done.connect(self._on_inbox_done)
        w.start()
        self._workers.append(w)

    def _on_inbox_done(self, result, err):
        for i in reversed(range(self._inbox_layout.count())):
            item = self._inbox_layout.itemAt(i)
            if item and item.widget() and item.widget() != self._inbox_placeholder:
                item.widget().deleteLater()

        if err:
            self._inbox_placeholder.setText(f"Error: {err}")
            return
        grants, api_err = result
        if api_err:
            self._inbox_placeholder.setText(f"Error: {api_err}")
            return
        if not grants:
            self._inbox_placeholder.setText("Nothing shared with you yet.")
            return
        self._inbox_placeholder.hide()

        for g in grants:
            row = GrantRow(g, show_revoke=False)
            self._inbox_layout.addWidget(row)

    # ── Profile ───────────────────────────────────────────────────────────────
    def _build_profile(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        layout.addWidget(SectionHeader("Profile & Security"))

        # Info card
        self._profile_card = Card()
        pc = QVBoxLayout(self._profile_card)
        pc.setContentsMargins(24, 20, 24, 20)
        pc.setSpacing(10)
        pc.addWidget(SubLabel("Loading profile…"))
        layout.addWidget(self._profile_card)

        # Public key card
        pk_card = Card()
        pk_layout = QVBoxLayout(pk_card)
        pk_layout.setContentsMargins(24, 20, 24, 20)
        pk_layout.setSpacing(10)
        pk_layout.addWidget(SectionHeader("Your Public Key"))
        pk_layout.addWidget(SubLabel("Share this with others so they can grant you access to their records."))

        self._pubkey_text = QTextEdit()
        self._pubkey_text.setReadOnly(True)
        self._pubkey_text.setFixedHeight(80)
        self._pubkey_text.setPlaceholderText("Public key will appear here after loading…")
        pk_layout.addWidget(self._pubkey_text)

        copy_btn = QPushButton("Copy Public Key")
        copy_btn.setFixedHeight(36)
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self._pubkey_text.toPlainText()))
        pk_layout.addWidget(copy_btn)
        layout.addWidget(pk_card)

        # Rotate key
        rot_card = Card()
        rot_card.setStyleSheet(f"""
            #Card {{
                background: {C['surface']};
                border: 1px solid {C['error']};
                border-radius: 12px;
            }}
        """)
        rl = QVBoxLayout(rot_card)
        rl.setContentsMargins(24, 20, 24, 20)
        rl.setSpacing(10)
        rl.addWidget(SectionHeader("⚠ Rotate Keypair"))
        rl.addWidget(SubLabel("Generates a new P-256 keypair, re-wraps all DEKs, and revokes all existing grants."))
        rot_btn = QPushButton("Rotate My Key")
        rot_btn.setFixedHeight(38)
        rot_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent; border: 1px solid {C['red']};
                border-radius: 8px; color: {C['red']};
                font-size: 13px; font-weight: 600;
            }}
            QPushButton:hover {{ background: {C['error']}22; }}
        """)
        rot_btn.clicked.connect(self._do_rotate_key)
        rl.addWidget(rot_btn)
        layout.addWidget(rot_card)

        layout.addStretch()
        outer.addWidget(self._scrollable(inner))
        return page

    def _load_profile(self):
        def _work():
            profile, err = _get(self.base_url, "/api/auth/me", self.token)
            pubkey = None
            pem = load_key(self.username)
            if pem:
                try:
                    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                    from cryptography.hazmat.primitives.serialization import load_pem_private_key
                    priv = load_pem_private_key(pem.encode(), password=None)
                    raw  = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                    pubkey = raw.hex()
                except Exception:
                    pass
            return profile, pubkey, err

        w = ApiWorker(_work)
        w.done.connect(self._on_profile_done)
        w.start()
        self._workers.append(w)

    def _on_profile_done(self, result, err):
        profile, pubkey, api_err = result or ({}, None, str(err))

        # Clear profile card
        for i in reversed(range(self._profile_card.layout().count())):
            self._profile_card.layout().itemAt(i).widget().deleteLater()

        if api_err or not profile:
            lbl = QLabel(f"Error: {api_err or 'failed to load'}")
            lbl.setStyleSheet(f"color: {C['red']};")
            self._profile_card.layout().addWidget(lbl)
            return

        fields = [
            ("User ID",      profile.get("user_id", "—")),
            ("Email",        profile.get("email",    "—")),
            ("Username",     profile.get("username", "—")),
            ("Full Name",    profile.get("full_name","—")),
            ("Role",         profile.get("role",     "—")),
            ("Account Active", str(profile.get("is_active", "—"))),
            ("Last Login",   str(profile.get("last_login", "—"))[:19]),
            ("Key Hash",     (profile.get("public_key_hash","")[:32] + "…") if profile.get("public_key_hash") else "—"),
        ]
        for label, value in fields:
            row = QHBoxLayout()
            k = QLabel(label)
            k.setStyleSheet(f"font-size: 12px; color: {C['text2']}; min-width: 120px;")
            v = QLabel(value)
            v.setStyleSheet(f"font-size: 13px; color: {C['text']}; font-family: monospace;")
            v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(k)
            row.addWidget(v, 1)
            self._profile_card.layout().addLayout(row)

        if pubkey:
            self._pubkey_text.setText(pubkey)

    def _do_rotate_key(self):
        confirm = QMessageBox.question(self, "Rotate Keypair",
            "This will:\n• Generate a new P-256 keypair\n• Re-encrypt all your records\n• Revoke ALL existing grants\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm != QMessageBox.StandardButton.Yes:
            return

        pem = load_key(self.username)
        if not pem:
            QMessageBox.warning(self, "No Key", "Private key not found.")
            return

        def _work():
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PrivateFormat, PublicFormat, NoEncryption)
            new_priv = ec.generate_private_key(ec.SECP256R1())
            new_pem  = new_priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
            pub_raw  = new_priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            new_pub_hex = pub_raw.hex()
            res, err = _post(self.base_url, "/api/vault/rotate-key", {
                "old_private_key_pem": pem,
                "new_private_key_pem": new_pem,
                "new_public_key_hex":  new_pub_hex,
            }, self.token)
            if err:
                return None, err
            save_key(self.username, new_pem)
            return res, None

        def _on_done(result, err):
            if err:
                QMessageBox.critical(self, "Key Rotation Failed", str(err))
                return
            res, api_err = result
            if api_err:
                QMessageBox.critical(self, "Key Rotation Failed", api_err)
                return
            QMessageBox.information(self, "Key Rotated",
                f"✓ Key rotated successfully.\n"
                f"Records re-wrapped: {res.get('rotated_records', '?')}\n"
                f"Grants revoked: {res.get('revoked_grants', '?')}")
            self._load_profile()

        w = ApiWorker(_work)
        w.done.connect(_on_done)
        w.start()
        self._workers.append(w)


# ── Main Window ────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.setWindowTitle("MedLedger — Health Vault")
        self.setMinimumSize(1100, 700)
        self.resize(1260, 800)

        self._bg_widget = QWidget()
        self._bg_widget.setStyleSheet(f"background: {C['bg']};")
        self.setCentralWidget(self._bg_widget)
        self._root = QVBoxLayout(self._bg_widget)
        self._root.setContentsMargins(0, 0, 0, 0)

        self._stack = QStackedWidget()
        self._root.addWidget(self._stack)

        self._login_page = LoginPage(base_url)
        self._login_page.login_success.connect(self._on_login)
        self._login_page.switch_register.connect(self._show_register)

        self._register_page = RegisterPage(base_url)
        self._register_page.register_success.connect(self._on_register_success)
        self._register_page.switch_login.connect(self._show_login)

        self._stack.addWidget(self._login_page)      # 0
        self._stack.addWidget(self._register_page)   # 1
        self._stack.setCurrentIndex(0)

        self._dashboard = None

    def _show_login(self):
        self._stack.setCurrentIndex(0)

    def _show_register(self):
        self._stack.setCurrentIndex(1)

    def _on_login(self, token, username, profile):
        self._load_dashboard(token, username, profile)

    def _on_register_success(self, username):
        QMessageBox.information(self, "Account Created",
            f"✓ Account created for '{username}'.\n"
            f"Your private key is saved at .env/{username}.pem\n\n"
            "Please log in now.")
        self._show_login()

    def _load_dashboard(self, token, username, profile):
        if self._dashboard:
            self._stack.removeWidget(self._dashboard)
            self._dashboard.deleteLater()

        self._dashboard = DashboardPage(self.base_url, token, username, profile)
        self._dashboard.logout_requested.connect(self._on_logout)
        self._stack.addWidget(self._dashboard)
        self._stack.setCurrentWidget(self._dashboard)

    def _on_logout(self):
        if self._dashboard:
            self._stack.setCurrentIndex(0)
            self._stack.removeWidget(self._dashboard)
            self._dashboard.deleteLater()
            self._dashboard = None


# ── Entry ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MedLedger Desktop GUI")
    parser.add_argument("--base-url", default=DEFAULT_BASE)
    args = parser.parse_args()

    app = QApplication(sys.argv)
    app.setApplicationName("MedLedger")
    app.setStyleSheet(QSS)

    win = MainWindow(args.base_url)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
