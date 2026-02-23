# MedLedger: How to Use - Complete System Guide
## For Patients, Doctors, Admins, and Developers

---

## TABLE OF CONTENTS

1. [For Patients](#for-patients)
2. [For Doctors](#for-doctors)
3. [For Administrators](#for-administrators)
4. [For Developers](#for-developers)
5. [Troubleshooting](#troubleshooting)

---

## FOR PATIENTS

### 🔐 Your Role
You control your medical data. Every access requires your permission. You can revoke access instantly.

### Getting Started

#### Step 1: Register
```
1. Go to http://localhost:3000/register
2. Enter username, email, password
3. System generates ECDSA P-256 keypair
4. SAVE YOUR PRIVATE KEY (download and store safely!)
   - This is the only key to your data
   - If you lose it, you can use recovery process
5. Confirm email (check inbox)
```

**Important:** Your private key is NEVER sent to the server. Only you have it.

#### Step 2: Log In
```
1. Go to http://localhost:3000/login
2. Enter username and password
3. You'll see your dashboard
```

### Managing Your Records

#### Upload Medical Record
```
1. Dashboard → "Upload Record"
2. Select file (PDF, images, text)
3. Add description (e.g., "Cancer Diagnosis 2024")
4. Click "Upload"
   → Record is encrypted with AES-256
   → Stored securely
   → You keep the key
```

#### View Your Records
```
1. Dashboard → "My Records"
2. See all records you've uploaded
3. Click record to view details
4. See who has access
5. Click "Download" to get your copy
```

### Granting Access

#### Give Doctor Permission
```
1. Dashboard → "Grant Access"
2. Select doctor:
   - Enter doctor ID or search by name
3. Select record:
   - Choose which record they can see
4. Set time window:
   - "2 hours" means access is valid for 2 hours only
   - After that, automatic denial
   - You can revoke anytime before window ends
5. Set permission level:
   - "View Only" (doctor can see, not download)
   - "View & Download" (doctor can download copy)
6. Click "Grant Access with Signature"
   → System signs permission with YOUR private key
   → Doctor can never fake this (they don't have your key)
   → Signature proves YOU authorized this
```

#### Revoke Access (One-Click)
```
1. Dashboard → "Active Permissions"
2. Find doctor/permission you want to revoke
3. Click "Revoke Access"
   → Access denied immediately
   → Next attempt shows error
   → Logged to audit trail
```

### Checking Your Audit Trail

```
1. Dashboard → "Audit Trail"
2. See ALL access attempts:
   - Successful access
   - Failed access (admin tried?)
   - Permission grants
   - Permission revocations
3. Click entry to see details:
   - Who tried
   - When
   - Which record
   - Result (allowed/denied)
   - Why (if denied)
4. **Key insight:** Can't be faked or deleted
   - Logged on blockchain
   - Permanent proof
   - Shows if anyone tried to access without permission
```

### Lost Your Private Key?

```
1. Dashboard → "Security"
2. Click "Recover Access"
3. Verify identity:
   - Confirm email (code sent to inbox)
   - Answer security questions
4. Request recovery from 3 trustees:
   - Doctor (must approve)
   - Family member (must approve)
   - Hospital (must approve)
5. System recovers from Shamir fragments
6. You get temporary 72-hour key
7. Set new permanent key
```

---

## FOR DOCTORS

### 🏥 Your Role
Request access to patient records. Verify you have permission before viewing.

### Getting Started

#### Register
```
1. Go to http://localhost:3000/register
2. Select "Doctor" role
3. Enter credentials
4. Verify email
5. You now have public key for cryptographic verification
```

#### Log In
```
1. http://localhost:3000/login
2. Enter credentials
3. See your dashboard
```

### Accessing Patient Records

#### Request Access
```
1. Search for patient:
   - Dashboard → "Find Patient"
   - Enter patient username or ID
2. Click patient → see their records
3. Click record → "Request Access"
4. Message to patient (optional):
   - "Need to review lab results for checkup"
5. Click "Send Request"
   → Patient gets notification
   → They must approve
   → Can set custom time window
```

#### View Record (After Permission Granted)
```
1. Check notifications:
   - "Patient Alice granted access to Cancer Diagnosis"
   - Shows permission window: "Valid 2pm-4pm"
2. Click "View Record"
3. System verifies:
   ✓ Permission exists
   ✓ Signature is valid (Alice authorized)
   ✓ Current time is within window
   ✓ Access granted!
4. Record is decrypted and shown
5. Audit trail logs: "Dr. Smith accessed at 2:30pm"
```

#### Audit Trail (Your Access History)
```
1. Dashboard → "My Access Log"
2. See all records you've accessed
3. Shows:
   - Patient name
   - Record name
   - Time accessed
   - Permission duration
   - Status (successful/denied)
```

### What If Access is Denied?

```
Scenarios:
1. "No active permission"
   → Patient hasn't granted access yet
   → Action: Send request and wait

2. "Permission expired"
   → Time window ended
   → Action: Ask patient for new permission
   → They can grant again instantly

3. "Signature verification failed"
   → Someone tried to fake permission
   → This should NEVER happen in normal use
   → Action: Contact patient/admin

4. "Permission revoked"
   → Patient changed their mind
   → Action: Respect their choice
   → Action: Ask politely for new permission
```

---

## FOR ADMINISTRATORS

### ⚠️ Your Role
Monitor system. Handle compliance. **Cannot override patient security.**

### System Access

```
1. Admin login (special role)
2. Dashboard shows:
   - System health
   - Number of users
   - Permissions granted
   - Access logs
```

### What You Can Do

#### View System Audit Trail
```
1. Admin Panel → "System Audit"
2. See all system events:
   - User registrations
   - Permission grants
   - Access attempts (successful and failed)
   - Revocations
3. Filter by:
   - Time range
   - Patient
   - Doctor
   - Action type
```

#### Generate Compliance Reports
```
1. Admin Panel → "Reports"
2. "HIPAA Audit Trail"
   → Proves security controls
   → Shows access control enforcement
   → Immutable log (can't be deleted)
3. "Access Summary"
   → Who accessed what
   → When
   → For how long
   → Patient approval for each
```

#### Investigate Suspicious Activity
```
1. Admin Panel → "Alerts"
2. If access attempt failed:
   - "Admin user X tried to access record Y without permission"
   - "Patient Alice: Permission not found"
   - "Action logged to blockchain"
3. Click to investigate:
   - Who tried
   - When
   - Which record
   - Why it failed (no valid signature)
4. **Key point:** Math prevented the breach
   - Admin can't fake patient signature
   - No matter how much DB access they have
```

### What You CANNOT Do (By Design)

```
❌ Override patient permissions
   → Would require patient's private key
   → Which only patient has

❌ Delete audit logs
   → Logs on blockchain
   → Tamper-proof

❌ Give yourself access
   → No signature from patient
   → System denies

❌ See patient's private key
   → Stored only on patient's device
   → Never transmitted to server

❌ Modify permission time windows
   → Signature would fail verification
   → System detects tampering
```

**This is by design!** Healthcare data is sacred. Admin controls are limited to monitoring, not bypassing security.

---

## FOR DEVELOPERS

### 🛠️ System Architecture

```
Frontend (React)
    ↓
API Gateway (FastAPI)
    ↓
┌─────────────────────┐
├─ Crypto Layer      │  (ECDSA P-256, AES-256-GCM, Shamir)
├─ Permission Layer  │  (Grant, Verify, Revoke)
├─ Audit Layer       │  (Blockchain, Immutable logs)
└─ Storage Layer     │  (Encrypted records, DB)
```

### Running the System Locally

#### Start Backend
```bash
cd medledger-backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or: venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements.txt

# Create .env
cp .env.example .env
# Edit .env with your settings

# Initialize database
python -c "from src.database.models import Base, engine; Base.metadata.create_all(engine)"

# Run server
uvicorn src.api.main:app --reload --port 8000
```

#### Start Frontend
```bash
cd medledger-frontend

# Install dependencies
npm install

# Create .env
cp .env.example .env
# Make sure VITE_API_URL=http://localhost:8000

# Run dev server
npm run dev
```

#### Open in Browser
```
Frontend: http://localhost:5173
Swagger UI (API Docs): http://localhost:8000/docs
```

### Testing APIs Directly

#### Test 1: Register Patient
```bash
curl -X POST "http://localhost:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePassword123!",
    "role": "PATIENT"
  }'

# Response:
# {
#   "user_id": "uuid",
#   "username": "alice",
#   "public_key_hash": "abc123...",
#   "access_token": "eyJ0eXAi..."
# }
```

#### Test 2: Generate Keypair (In Code)
```python
from src.crypto.key_manager import KeyManager

manager = KeyManager()
keypair = manager.generate_keypair()

print(f"Public Key: {keypair.public_key_hex}")
print(f"Private Key: {keypair.private_key_pem}")
```

#### Test 3: Grant Permission
```bash
curl -X POST "http://localhost:8000/permissions/grant" \
  -H "Content-Type: application/json" \
  -d '{
    "patient_id": "alice-uuid",
    "doctor_id": "smith-uuid",
    "record_id": "cancer-diag-uuid",
    "time_window_hours": 2,
    "permission_level": "view_only",
    "patient_private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'
```

#### Test 4: Verify Permission
```bash
curl -X POST "http://localhost:8000/permissions/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "doctor_id": "smith-uuid",
    "record_id": "cancer-diag-uuid",
    "patient_public_key_hex": "04abc123..."
  }'

# Response if allowed:
# { "allowed": true, "permission_id": "perm-123" }

# Response if denied:
# { "allowed": false, "reason": "Signature verification failed" }
```

### Key Files to Understand

| File | Purpose |
|------|---------|
| `src/api/main.py` | FastAPI app entry point |
| `src/api/routes/permissions.py` | Permission endpoints |
| `src/services/permission_service.py` | Permission business logic |
| `src/crypto/signature_verifier.py` | ECDSA signing/verification |
| `src/database/models.py` | Database schema |
| `src/crypto/key_manager.py` | Key generation |

### Database Schema

```
Users Table
├─ id (UUID)
├─ username (unique)
├─ email (unique)
├─ public_key_hex
├─ password_hash (for login only, not key)
└─ role (PATIENT, DOCTOR, ADMIN)

Permissions Table
├─ id (UUID)
├─ patient_id
├─ doctor_id
├─ record_id
├─ signature (ECDSA)
├─ permission_data (JSON)
├─ time_start
├─ time_end
└─ is_revoked

AuditLog Table
├─ id (UUID)
├─ action (PERMISSION_GRANTED, ACCESS_ATTEMPT, etc.)
├─ patient_id
├─ doctor_id
├─ record_id
├─ details
└─ timestamp
```

### Common Development Tasks

#### Debug: Check Why Access Was Denied
```bash
# Check audit log
curl "http://localhost:8000/permissions/audit?record_id=cancer-diag" | jq '.'

# Look for entries like:
# {
#   "timestamp": "2024-02-16T14:30:00",
#   "action": "ACCESS_ATTEMPT",
#   "doctor_id": "smith",
#   "record_id": "cancer-diag",
#   "details": "DENIED: Signature verification failed"
# }
```

#### Debug: Verify Signature Manually
```python
from src.crypto.signature_verifier import SignatureVerifier

verifier = SignatureVerifier()

# Data that was signed
permission_data = {
    "patient_id": "alice",
    "doctor_id": "smith",
    "record_id": "cancer-diag",
    "time_start": "2024-02-16T14:00:00",
    "time_end": "2024-02-16T16:00:00",
    "permission_level": "view_only"
}

# Verify signature
is_valid, reason = verifier.verify_signature(
    public_key_hex="04abc123...",
    signature_hex="3045022100...",
    permission_data=permission_data
)

if is_valid:
    print("✓ Signature is valid (patient authorized this)")
else:
    print(f"✗ Signature invalid: {reason}")
```

### Running Tests
```bash
# Backend unit tests
pytest tests/

# Frontend tests
npm test

# Integration tests (requires both running)
pytest tests/integration/
```

---

## TROUBLESHOOTING

### "Login Failed"
```
Causes:
1. Username/password wrong
   → Check caps lock
   → Make sure you registered first

2. User not found
   → Did you register?
   → Try again

3. Database not initialized
   → Run: python -c "from src.database.models import Base, engine; Base.metadata.create_all(engine)"
```

### "Grant Access Failed"
```
Causes:
1. Private key not found
   → Did you save your private key at registration?
   → Check localStorage in browser console
   → localStorage.getItem('private_key_pem')

2. Invalid doctor ID
   → Does the doctor exist?
   → Check their user ID

3. Invalid record ID
   → Does the record exist?
   → Check your uploads

Solutions:
→ Check browser console for error details
→ Look at server logs: uvicorn output
→ Check audit trail for failed attempts
```

### "Permission Denied When Doctor Tries to Access"
```
Possible reasons:
1. Time window expired
   → Ask patient for new permission
   → They can grant instantly

2. No permission exists
   → Patient hasn't granted yet
   → Send request and wait

3. Signature verification failed
   → Something was modified
   → Contact patient/admin

4. Permission was revoked
   → Patient revoked access
   → Respect their choice

Debug:
→ Check audit trail
→ Look for "ACCESS_ATTEMPT" entries
→ See the reason field
```

### "Can't Download Private Key"
```
The private key is generated during registration.
Where is it?

1. **Browser storage:**
   ```javascript
   // In browser console:
   localStorage.getItem('private_key_pem')
   ```

2. **Downloaded file:**
   Check your Downloads folder for "private-key.pem"

3. **Lost it?**
   Use key recovery:
   Dashboard → Security → Recover Access
   (Requires email verification + 3 trustees)
```

### "Can't Connect to Backend"
```
Error: "Failed to fetch from http://localhost:8000"

Fixes:
1. Is backend running?
   → Check terminal: "Uvicorn running on..."

2. Wrong port?
   → Backend on 8000?
   → Check .env: API_URL=http://localhost:8000

3. CORS error?
   → Frontend on 5173?
   → Backend must allow CORS
   → Check main.py CORS config

4. Network issue?
   → Try: curl http://localhost:8000/
   → Should return JSON response
```

### "Audit Trail Not Showing"
```
Issues:
1. No permissions granted yet
   → Grant one first
   → Then check audit trail

2. Database not initialized
   → Run: python -m src.database.models

3. API returning error
   → Check browser network tab
   → See API response
   → Check server logs
```

---

## NEXT STEPS

- **For Patients:** Start with [Getting Started](#getting-started)
- **For Doctors:** See [Accessing Patient Records](#accessing-patient-records)
- **For Admins:** Check [System Access](#system-access)
- **For Developers:** Follow [Running the System Locally](#running-the-system-locally)

---

**Questions?** Check the troubleshooting section or review the architecture diagrams in the docs folder.

**Ready to use MedLedger?** Let's go! 🏥🔐
