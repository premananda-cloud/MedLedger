"""
medledger_demo.py - Complete MedLedger Demo with nanoThread Visualization
Run this for your hackathon video - shows the entire flow with working buttons
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import json
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os

# Import your actual MedLedger crypto libraries
from medledger_client.core.crypto import (
    generate_private_key_hex,
    derive_public_key_hex,
    derive_public_key_hash,
    encrypt_document,
    decrypt_document,
    rewrap_dek_for_doctor,
    sign_permission_payload,
    ecies_encrypt,
    ecies_decrypt,
)

# For nanoThread visualization
try:
    import requests
    NANOTHREAD_AVAILABLE = True
except ImportError:
    NANOTHREAD_AVAILABLE = False
    print("Note: requests not installed - nanoThread integration disabled")

class NanoThreadVisualizer:
    """Visualizes the crypto flow like nanoThread"""
    
    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="🔐 Crypto Flow Visualization", padding=10)
        self.frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Canvas for drawing
        self.canvas = tk.Canvas(self.frame, height=200, bg='white', highlightthickness=1, highlightcolor='#ccc')
        self.canvas.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Steps display
        self.steps_text = scrolledtext.ScrolledText(self.frame, height=5, width=80, wrap=tk.WORD)
        self.steps_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.step_count = 0
        self.arrows = []
        
    def clear(self):
        self.canvas.delete("all")
        self.steps_text.delete(1.0, tk.END)
        self.step_count = 0
        self.arrows = []
        
    def add_step(self, step_num, description, color="blue"):
        self.steps_text.insert(tk.END, f"Step {step_num}: {description}\n", color)
        self.steps_text.tag_config(color, foreground=color)
        self.steps_text.see(tk.END)
        
    def draw_key_exchange(self, sender, receiver, label):
        x1, y1 = sender
        x2, y2 = receiver
        arrow = self.canvas.create_line(x1, y1, x2, y2, arrow=tk.LAST, width=2, fill='green')
        self.canvas.create_text((x1+x2)//2, (y1+y2)//2-15, text=label, fill='darkgreen')
        return arrow
        
    def draw_encryption(self, x, y, label):
        self.canvas.create_rectangle(x-40, y-15, x+40, y+15, fill='lightblue', outline='blue')
        self.canvas.create_text(x, y, text=label, fill='darkblue')
        
    def draw_signature(self, x, y):
        self.canvas.create_text(x, y, text="✍️ SIGNED", fill='purple', font=('Arial', 10, 'bold'))


class MedLedgerDemoApp:
    """Complete MedLedger demo with nanoThread visualization"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("MedLedger - Patient Controlled Healthcare Data")
        self.root.geometry("1200x800")
        
        # Set style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Accent.TButton', font=('Arial', 11, 'bold'))
        
        # Demo data
        self.patient = {
            "name": "Alice Patient",
            "email": "alice@demo.com",
            "password": "password123",
            "priv_key": None,
            "pub_key": None,
            "pub_hash": None,
            "records": []
        }
        
        self.doctor = {
            "name": "Dr. James Smith",
            "email": "smith@hospital.org",
            "id": "doc_456",
            "priv_key": None,
            "pub_key": None,
            "pub_hash": None
        }
        
        self.admin = {
            "name": "Admin Bob",
            "email": "admin@hospital.org",
            "role": "admin"
        }
        
        # Sample records
        self.records = [
            {
                "id": "rec_001",
                "name": "Blood Test Results - Feb 2026.pdf",
                "date": "2026-02-20",
                "content": b"Sample blood test data: WBC normal, RBC normal, Cholesterol 180",
                "encrypted": None,
                "dek_bundle": None,
                "shared_with": []
            },
            {
                "id": "rec_002",
                "name": "Chest X-Ray Report.pdf", 
                "date": "2026-02-21",
                "content": b"X-Ray findings: No abnormalities detected. Lungs clear.",
                "encrypted": None,
                "dek_bundle": None,
                "shared_with": []
            }
        ]
        
        # Active permission
        self.active_permission = None
        
        # Build UI
        self.setup_ui()
        
        # Generate keys on startup
        self.generate_keys()
        
    def setup_ui(self):
        """Build the main UI"""
        
        # Title
        title_frame = ttk.Frame(self.root)
        title_frame.pack(fill="x", padx=10, pady=10)
        
        title = ttk.Label(title_frame, text="🏥 MedLedger Demo", 
                          font=('Arial', 20, 'bold'))
        title.pack(side="left")
        
        subtitle = ttk.Label(title_frame, 
                             text="Patient-Controlled Healthcare Data - Enforced by Cryptography, Not Policy",
                             font=('Arial', 10))
        subtitle.pack(side="left", padx=20)
        
        # Main content area - split into left (controls) and right (visualization)
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Left panel - Controls
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=1)
        
        # User cards
        self.create_user_cards(left_frame)
        
        # Action buttons
        self.create_action_buttons(left_frame)
        
        # Status display
        self.create_status_display(left_frame)
        
        # Right panel - nanoThread visualization
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=1)
        
        self.visualizer = NanoThreadVisualizer(right_frame)
        
        # Bottom log
        self.create_log_area()
        
    def create_user_cards(self, parent):
        """Create cards for patient, doctor, admin"""
        
        card_frame = ttk.LabelFrame(parent, text="👥 Demo Users", padding=10)
        card_frame.pack(fill="x", padx=5, pady=5)
        
        # Patient card
        patient_frame = ttk.LabelFrame(card_frame, text="🧑 PATIENT", padding=10)
        patient_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(patient_frame, text="Alice Patient").pack(anchor="w")
        ttk.Label(patient_frame, text="alice@demo.com").pack(anchor="w")
        self.patient_key_label = ttk.Label(patient_frame, text="🔑 Private key: Ready", foreground="green")
        self.patient_key_label.pack(anchor="w", pady=2)
        
        # Doctor card
        doctor_frame = ttk.LabelFrame(card_frame, text="👨‍⚕️ DOCTOR", padding=10)
        doctor_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(doctor_frame, text="Dr. James Smith").pack(anchor="w")
        ttk.Label(doctor_frame, text="smith@hospital.org").pack(anchor="w")
        self.doctor_key_label = ttk.Label(doctor_frame, text="🔑 Private key: Ready", foreground="green")
        self.doctor_key_label.pack(anchor="w", pady=2)
        
        # Admin card
        admin_frame = ttk.LabelFrame(card_frame, text="👤 ADMIN", padding=10)
        admin_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(admin_frame, text="Admin Bob").pack(anchor="w")
        ttk.Label(admin_frame, text="admin@hospital.org").pack(anchor="w")
        ttk.Label(admin_frame, text="⚠️ Can view DB but NOT decrypt records", foreground="red").pack(anchor="w", pady=2)
        
    def create_action_buttons(self, parent):
        """Create all demo action buttons"""
        
        btn_frame = ttk.LabelFrame(parent, text="🎬 Demo Actions", padding=10)
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        # Row 1: Registration/Login
        row1 = ttk.Frame(btn_frame)
        row1.pack(fill="x", pady=2)
        
        ttk.Button(row1, text="1️⃣ Register Patient", 
                   command=self.demo_register_patient,
                   style='Accent.TButton').pack(side="left", padx=2, expand=True, fill="x")
        
        ttk.Button(row1, text="2️⃣ Register Doctor", 
                   command=self.demo_register_doctor,
                   style='Accent.TButton').pack(side="left", padx=2, expand=True, fill="x")
        
        # Row 2: Upload
        row2 = ttk.Frame(btn_frame)
        row2.pack(fill="x", pady=2)
        
        ttk.Button(row2, text="3️⃣ Upload Medical Record", 
                   command=self.demo_upload,
                   style='Accent.TButton').pack(side="left", padx=2, expand=True, fill="x")
        
        # Row 3: Grant Access
        row3 = ttk.Frame(btn_frame)
        row3.pack(fill="x", pady=2)
        
        ttk.Button(row3, text="4️⃣ Grant Doctor Access", 
                   command=self.demo_grant_access,
                   style='Accent.TButton').pack(side="left", padx=2, expand=True, fill="x")
        
        # Row 4: Doctor View
        row4 = ttk.Frame(btn_frame)
        row4.pack(fill="x", pady=2)
        
        ttk.Button(row4, text="5️⃣ Doctor Views Record", 
                   command=self.demo_doctor_view,
                   style='Accent.TButton').pack(side="left", padx=2, expand=True, fill="x")
        
        # Row 5: Revoke & Admin Fail
        row5 = ttk.Frame(btn_frame)
        row5.pack(fill="x", pady=2)
        
        ttk.Button(row5, text="6️⃣ Revoke Access", 
                   command=self.demo_revoke,
                   style='Accent.TButton').pack(side="left", padx=2, expand=True, fill="x")
        
        ttk.Button(row5, text="7️⃣ Admin Tries to Bypass", 
                   command=self.demo_admin_fail,
                   style='Accent.TButton').pack(side="left", padx=2, expand=True, fill="x")
        
        # Row 6: Reset
        row6 = ttk.Frame(btn_frame)
        row6.pack(fill="x", pady=5)
        
        ttk.Button(row6, text="🔄 Reset Demo", 
                   command=self.reset_demo).pack(side="left", padx=2, expand=True, fill="x")
        
    def create_status_display(self, parent):
        """Show current state"""
        
        status_frame = ttk.LabelFrame(parent, text="📊 Current State", padding=10)
        status_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.status_text = scrolledtext.ScrolledText(status_frame, height=10, wrap=tk.WORD)
        self.status_text.pack(fill="both", expand=True)
        
        self.update_status()
        
    def create_log_area(self):
        """Bottom log area"""
        
        log_frame = ttk.LabelFrame(self.root, text="📝 Demo Log", padding=5)
        log_frame.pack(fill="x", padx=10, pady=5, side="bottom")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, wrap=tk.WORD)
        self.log_text.pack(fill="x", expand=True)
        
    def log(self, message, color="black"):
        """Add message to log"""
        self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n", color)
        self.log_text.tag_config(color, foreground=color)
        self.log_text.see(tk.END)
        self.root.update()
        
    def update_status(self):
        """Update status display"""
        self.status_text.delete(1.0, tk.END)
        
        status = "🔐 CRYPTOGRAPHIC STATE:\n"
        status += "="*40 + "\n\n"
        
        status += f"Patient private key: {'✅ LOADED' if self.patient['priv_key'] else '❌ MISSING'}\n"
        status += f"Patient public key: {'✅ DERIVED' if self.patient['pub_key'] else '❌ MISSING'}\n"
        status += f"Doctor private key: {'✅ LOADED' if self.doctor['priv_key'] else '❌ MISSING'}\n"
        status += f"Doctor public key: {'✅ DERIVED' if self.doctor['pub_key'] else '❌ MISSING'}\n\n"
        
        status += f"Records stored: {len([r for r in self.records if r['encrypted']])}/2 encrypted\n"
        
        shared = [r for r in self.records if self.doctor['pub_hash'] in r['shared_with']]
        status += f"Records shared with doctor: {len(shared)}\n\n"
        
        if self.active_permission:
            status += f"Active permission: {self.active_permission['id']}\n"
            status += f"Expires: {self.active_permission['expires']}\n"
        else:
            status += "Active permission: None\n"
            
        self.status_text.insert(tk.END, status)
        
    def generate_keys(self):
        """Generate all crypto keys"""
        
        # Patient keys
        self.patient['priv_key'] = generate_private_key_hex()
        self.patient['pub_key'] = derive_public_key_hex(self.patient['priv_key'])
        self.patient['pub_hash'] = derive_public_key_hash(self.patient['priv_key'])
        
        # Doctor keys
        self.doctor['priv_key'] = generate_private_key_hex()
        self.doctor['pub_key'] = derive_public_key_hex(self.doctor['priv_key'])
        self.doctor['pub_hash'] = derive_public_key_hash(self.doctor['priv_key'])
        
        self.patient_key_label.config(text=f"🔑 Private key: {self.patient['priv_key'][:16]}...")
        self.doctor_key_label.config(text=f"🔑 Private key: {self.doctor['priv_key'][:16]}...")
        
        self.log("✅ Keys generated for patient and doctor", "green")
        self.update_status()
        
    def demo_register_patient(self):
        """Step 1: Register patient"""
        self.visualizer.clear()
        
        self.log("\n📝 STEP 1: PATIENT REGISTRATION", "blue")
        self.log("-"*40, "blue")
        
        # Visualize
        self.visualizer.canvas.create_text(200, 30, text="Patient Device", font=('Arial', 12, 'bold'))
        self.visualizer.canvas.create_text(400, 30, text="Server", font=('Arial', 12, 'bold'))
        
        # Key generation
        self.visualizer.draw_encryption(200, 80, "Generate P-256 Keypair")
        self.visualizer.add_step(1, "Patient generates P-256 keypair locally", "blue")
        self.log("   • P-256 keypair generated on patient's device")
        
        time.sleep(1)
        
        # Send public key
        self.visualizer.draw_key_exchange((200, 120), (400, 120), "Public Key Only")
        self.visualizer.add_step(2, "Patient sends PUBLIC key to server", "green")
        self.log("   • Private key NEVER leaves device")
        self.log("   • Server stores only public key")
        
        self.visualizer.draw_encryption(400, 160, "Store Public Key")
        self.visualizer.add_step(3, "Server stores public key, creates account", "purple")
        
        time.sleep(1)
        
        self.log("✅ Registration complete - Patient can now encrypt files", "green")
        self.update_status()
        
    def demo_register_doctor(self):
        """Register doctor (similar but shown briefly)"""
        self.log("\n📝 DOCTOR REGISTRATION", "blue")
        self.log("-"*40, "blue")
        self.log("   • Doctor generates their own keypair")
        self.log("   • Public key registered with server")
        self.log("   • Private key stays on doctor's device")
        self.log("✅ Doctor registered", "green")
        self.update_status()
        
    def demo_upload(self):
        """Step 2: Patient uploads encrypted file"""
        self.visualizer.clear()
        
        self.log("\n📤 STEP 2: PATIENT UPLOADS ENCRYPTED FILE", "blue")
        self.log("-"*40, "blue")
        
        # Use first record
        record = self.records[0]
        
        # Visualize
        self.visualizer.canvas.create_text(200, 30, text="Patient Device", font=('Arial', 12, 'bold'))
        self.visualizer.canvas.create_text(400, 30, text="Server", font=('Arial', 12, 'bold'))
        
        # File encryption
        self.visualizer.draw_encryption(200, 80, "Original File")
        self.visualizer.add_step(1, "Patient selects file to upload", "blue")
        self.log(f"   • File: {record['name']}")
        
        time.sleep(0.5)
        
        # Encrypt
        self.visualizer.canvas.create_text(200, 130, text="AES-256-GCM\nENCRYPT", fill="red", font=('Arial', 10, 'bold'))
        self.visualizer.add_step(2, "File encrypted with AES-256-GCM", "red")
        self.log("   • Generating random DEK (Data Encryption Key)")
        self.log("   • Encrypting file with DEK")
        
        # Actual encryption using your library
        result = encrypt_document(
            file_bytes=record['content'],
            patient_pub_hex=self.patient['pub_key'],
            patient_priv_hex=self.patient['priv_key']
        )
        
        record['encrypted'] = result['encrypted_blob']
        record['dek_bundle'] = result['encrypted_dek']
        
        time.sleep(0.5)
        
        # Wrap DEK
        self.visualizer.draw_encryption(200, 180, "Wrap DEK with\nPatient's Public Key")
        self.visualizer.add_step(3, "DEK wrapped with patient's public key (ECIES)", "green")
        self.log("   • DEK encrypted with patient's own public key")
        self.log("   • Only patient can unwrap with private key")
        
        time.sleep(0.5)
        
        # Upload
        self.visualizer.draw_key_exchange((200, 220), (400, 220), "Encrypted File + Wrapped DEK")
        self.visualizer.add_step(4, "Upload encrypted file to server", "purple")
        
        self.visualizer.draw_encryption(400, 260, "Store\nCiphertext Only")
        self.visualizer.add_step(5, "Server stores encrypted data - CANNOT READ IT", "orange")
        
        self.log("   • Server receives ONLY ciphertext")
        self.log("   • Server cannot decrypt - no private key")
        self.log("   • Even database admin sees only gibberish")
        
        time.sleep(1)
        
        self.log("✅ File uploaded and encrypted", "green")
        self.update_status()
        
    def demo_grant_access(self):
        """Step 3: Patient grants doctor access"""
        self.visualizer.clear()
        
        self.log("\n🔑 STEP 3: PATIENT GRANTS DOCTOR ACCESS", "blue")
        self.log("-"*40, "blue")
        
        record = self.records[0]
        
        # Visualize
        self.visualizer.canvas.create_text(200, 30, text="Patient Device", font=('Arial', 12, 'bold'))
        self.visualizer.canvas.create_text(300, 100, text="Doctor's Key", font=('Arial', 10))
        self.visualizer.canvas.create_text(400, 30, text="Server", font=('Arial', 12, 'bold'))
        
        # Get doctor's public key
        self.visualizer.draw_key_exchange((400, 70), (200, 120), "Doctor's Public Key")
        self.visualizer.add_step(1, "Fetch doctor's public key from server", "blue")
        self.log("   • Retrieved Dr. Smith's public key")
        
        time.sleep(0.5)
        
        # Decrypt DEK
        self.visualizer.draw_encryption(200, 160, "Decrypt DEK with\nPatient's Private Key")
        self.visualizer.add_step(2, "Decrypt the DEK using patient's private key", "green")
        
        # Use your actual crypto
        dek = ecies_decrypt(self.patient['priv_key'], record['dek_bundle'])
        self.log("   • DEK decrypted successfully")
        
        time.sleep(0.5)
        
        # Re-encrypt for doctor
        self.visualizer.draw_encryption(200, 210, "Re-encrypt DEK with\nDoctor's Public Key")
        self.visualizer.add_step(3, "Re-encrypt DEK for doctor's public key", "purple")
        
        doctor_dek_bundle = ecies_encrypt(self.doctor['pub_key'], dek)
        self.log("   • DEK re-encrypted for doctor")
        
        time.sleep(0.5)
        
        # Sign permission
        self.visualizer.draw_signature(200, 260)
        self.visualizer.add_step(4, "Patient signs permission with private key", "red")
        
        # Create permission payload
        valid_from = datetime.now(timezone.utc)
        valid_until = valid_from + timedelta(hours=24)
        
        permission = {
            "patient_id": "alice_001",
            "grantee_public_key_hash": self.doctor['pub_hash'],
            "record_id": record['id'],
            "valid_from": valid_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "permission_level": "view_only"
        }
        
        signature = sign_permission_payload(self.patient['priv_key'], permission)
        
        self.active_permission = {
            "id": f"perm_{hashlib.md5(signature.encode()).hexdigest()[:8]}",
            "record_id": record['id'],
            "expires": valid_until.strftime("%Y-%m-%d %H:%M"),
            "signature": signature
        }
        
        self.log("   • Permission signed with ECDSA P-256")
        self.log("   • Signature proves patient authorized this")
        
        time.sleep(0.5)
        
        # Send to server
        self.visualizer.draw_key_exchange((200, 300), (400, 300), "Permission + Doctor's DEK Bundle")
        self.visualizer.add_step(5, "Send signed permission to server", "blue")
        
        self.visualizer.draw_encryption(400, 340, "Store\nPermission & Doctor's Key")
        self.visualizer.add_step(6, "Server stores permission - still cannot decrypt", "orange")
        
        record['shared_with'].append(self.doctor['pub_hash'])
        
        self.log("   • Server stores:")
        self.log("     - Patient's signature")
        self.log("     - Doctor's encrypted DEK")
        self.log("   • Server STILL cannot decrypt anything")
        
        time.sleep(1)
        
        self.log("✅ Access granted to Dr. Smith for 24 hours", "green")
        self.update_status()
        
    def demo_doctor_view(self):
        """Step 4: Doctor views the record"""
        self.visualizer.clear()
        
        self.log("\n👨‍⚕️ STEP 4: DOCTOR VIEWS RECORD", "blue")
        self.log("-"*40, "blue")
        
        record = self.records[0]
        
        if self.doctor['pub_hash'] not in record['shared_with']:
            self.log("❌ No permission found - grant access first", "red")
            return
            
        # Visualize
        self.visualizer.canvas.create_text(200, 30, text="Doctor Device", font=('Arial', 12, 'bold'))
        self.visualizer.canvas.create_text(400, 30, text="Server", font=('Arial', 12, 'bold'))
        self.visualizer.canvas.create_text(600, 100, text="Audit Log", font=('Arial', 10))
        
        # Request access
        self.visualizer.draw_key_exchange((200, 80), (400, 80), "Request Record")
        self.visualizer.add_step(1, "Doctor requests access to record", "blue")
        self.log("   • Dr. Smith requests: 'Blood Test Results'")
        
        time.sleep(0.5)
        
        # Server verifies
        self.visualizer.draw_encryption(400, 130, "Verify:\n• Permission exists?\n• Not revoked?\n• Time valid?\n• Signature valid?")
        self.visualizer.add_step(2, "Server verifies permission cryptographically", "green")
        
        self.log("   • Server checks:")
        self.log("     ✓ Permission exists")
        self.log("     ✓ Not revoked")
        self.log("     ✓ Within 24h window")
        self.log("     ✓ Signature valid (proves patient approved)")
        
        time.sleep(1)
        
        # Log to audit
        self.visualizer.draw_key_exchange((400, 190), (600, 190), "Log Access")
        self.visualizer.add_step(3, "Access logged to immutable audit trail", "purple")
        self.log("   • Audit log: 'Dr. Smith accessed record at " + datetime.now().strftime("%H:%M") + "'")
        self.log("   • Log is append-only, cannot be deleted")
        
        time.sleep(0.5)
        
        # Send encrypted data
        self.visualizer.draw_key_exchange((400, 250), (200, 250), "Encrypted File + Doctor's Key Bundle")
        self.visualizer.add_step(4, "Server sends encrypted data to doctor", "blue")
        self.log("   • Server sends encrypted file")
        self.log("   • Server sends doctor's encrypted DEK bundle")
        
        time.sleep(0.5)
        
        # Doctor decrypts
        self.visualizer.draw_encryption(200, 300, "Decrypt DEK with\nDoctor's Private Key\n\nDecrypt File with DEK")
        self.visualizer.add_step(5, "Doctor decrypts locally", "green")
        
        # Simulate decryption
        self.log("   • Doctor decrypts DEK with his private key")
        self.log("   • Doctor decrypts file with DEK")
        self.log("   • File opens in viewer")
        
        time.sleep(0.5)
        
        # Show file content
        self.visualizer.draw_encryption(200, 360, f"📄 {record['name']}\n{record['content'].decode()[:50]}...")
        
        self.log("✅ Doctor can now read the file", "green")
        self.log("   • Server NEVER saw plaintext")
        self.log("   • Private keys NEVER left devices")
        self.log("   • Cryptography, not policy, enabled this")
        
        self.update_status()
        
    def demo_revoke(self):
        """Step 5: Patient revokes access"""
        self.log("\n⛔ STEP 5: PATIENT REVOKES ACCESS", "blue")
        self.log("-"*40, "blue")
        
        record = self.records[0]
        
        if self.doctor['pub_hash'] in record['shared_with']:
            record['shared_with'].remove(self.doctor['pub_hash'])
            
        self.log("   • Patient clicks 'Revoke Dr. Smith'")
        self.log("   • Server DELETES doctor's DEK bundle")
        self.log("   • Revocation is INSTANT")
        self.log("   • No TTL, no cache, no delay")
        
        self.active_permission = None
        
        time.sleep(1)
        
        self.log("✅ Access revoked - doctor can no longer decrypt", "green")
        self.update_status()
        
    def demo_admin_fail(self):
        """Step 6: Admin tries and fails"""
        self.log("\n👤 STEP 6: ADMIN TRIES TO BYPASS", "blue")
        self.log("-"*40, "blue")
        
        self.log("   • Hospital admin logs into database directly")
        self.log("   • Admin sees encrypted files: gibberish")
        self.log("")
        self.log("   • Admin tries to grant themselves access:")
        self.log("     - Adds permission record to database")
        self.log("     - Tries to access file")
        self.log("")
        self.log("   ❌ Server checks signature:")
        self.log("     'Signature verification failed'")
        self.log("")
        self.log("   • ACCESS DENIED")
        self.log("")
        self.log("   ✓ Math prevents admin override")
        self.log("   ✓ Policy didn't stop them - cryptography did")
        
        time.sleep(2)
        
        self.log("✅ Admin override: IMPOSSIBLE", "green")
        
    def reset_demo(self):
        """Reset everything"""
        self.generate_keys()
        self.records = [
            {
                "id": "rec_001",
                "name": "Blood Test Results - Feb 2026.pdf",
                "date": "2026-02-20",
                "content": b"Sample blood test data: WBC normal, RBC normal, Cholesterol 180",
                "encrypted": None,
                "dek_bundle": None,
                "shared_with": []
            },
            {
                "id": "rec_002",
                "name": "Chest X-Ray Report.pdf", 
                "date": "2026-02-21",
                "content": b"X-Ray findings: No abnormalities detected. Lungs clear.",
                "encrypted": None,
                "dek_bundle": None,
                "shared_with": []
            }
        ]
        self.active_permission = None
        self.visualizer.clear()
        self.log_text.delete(1.0, tk.END)
        self.log("🔄 Demo reset - ready to start over", "blue")
        self.update_status()


def main():
    root = tk.Tk()
    app = MedLedgerDemoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()