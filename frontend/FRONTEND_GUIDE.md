# MedLedger Frontend Integration Guide

A complete guide to building a frontend that connects to the MedLedger API.  
Written against the **live, tested API** — everything here has been verified to work.

---

## Table of Contents

1. [How the System Works](#1-how-the-system-works)
2. [Backend Setup](#2-backend-setup)
3. [Project Setup](#3-project-setup)
4. [API Reference](#4-api-reference)
5. [Auth Flow](#5-auth-flow)
6. [Permission Flow](#6-permission-flow)
7. [Storage Strategy](#7-storage-strategy)
8. [Full Code Examples](#8-full-code-examples)
9. [Role-Based UI](#9-role-based-ui)
10. [Error Handling](#10-error-handling)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. How the System Works

MedLedger uses **patient-controlled cryptographic access**. Understanding this model is essential before building any UI.

```
PATIENT                          DOCTOR
───────                          ──────
Registers → gets ECDSA keypair
Private key → saved by patient   Registers → gets their own keypair
Public key  → stored on server   Public key → stored on server

Patient grants access:
  - Signs permission with private key
  - Stores signature on server
                                 Doctor verifies access:
                                   - Sends patient's public key
                                   - Server checks signature is valid
                                   - Server checks time window
                                   - Server returns allowed: true/false
```

**Key rule:** The patient's private key is **returned once at registration and never stored on the server**. The frontend must save it. Without it, the patient cannot grant access to anyone.

---

## 2. Backend Setup

The frontend needs the backend running. From the project root:

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install fastapi uvicorn[standard] sqlalchemy pyjwt cryptography qrcode email-validator pydantic

# Set required environment variables
export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export DATABASE_URL="sqlite:///./medledger.db"

# Optional: allow your frontend's dev port
export ALLOWED_ORIGINS="http://localhost:5173,http://localhost:3000,http://localhost:8081"

# Start the server
uvicorn src.api.main:app --reload --port 8000
```

Verify it's running:
```bash
curl http://localhost:8000/health
# → {"status":"healthy","timestamp":"..."}
```

Interactive API docs (test endpoints in browser): **http://localhost:8000/docs**

---

## 3. Project Setup

### Create the app

```bash
npm create vite@latest medledger-frontend -- --template react-ts
cd medledger-frontend
npm install
```

### Install dependencies

```bash
npm install axios react-router-dom
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

### Environment file

Create `.env` in your frontend root:

```env
VITE_API_URL=http://localhost:8000
```

> If your frontend runs on a port other than 3000 or 8081, add it to `ALLOWED_ORIGINS` when starting the backend (see Section 2).

### Configure the API client

`src/services/api.ts`

```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  headers: { 'Content-Type': 'application/json' },
});

// Attach JWT token to every request automatically
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Redirect to login on token expiry
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.clear();
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
```

---

## 4. API Reference

### Base URL
```
http://localhost:8000
```

### Auth Endpoints

| Method | Path | Auth required | Description |
|--------|------|---------------|-------------|
| POST | `/api/auth/register` | No | Register new user |
| POST | `/api/auth/login` | No | Login, get JWT |
| GET | `/api/auth/me` | Yes | Get own profile |

### Permission Endpoints

| Method | Path | Auth required | Description |
|--------|------|---------------|-------------|
| POST | `/permissions/grant` | No* | Patient grants access |
| POST | `/permissions/verify` | No* | Doctor verifies access |
| POST | `/permissions/revoke` | No* | Patient revokes access |
| GET | `/permissions/patient/{id}` | No* | List patient's permissions |
| GET | `/permissions/audit` | No* | Get audit log |

> *These endpoints do not enforce the JWT on the server side currently — but you should always send it anyway for consistency and future-proofing.

### Headers

Every request after login must include:
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

---

## 5. Auth Flow

### Register

**POST** `/api/auth/register`

Request body:
```json
{
  "username": "alice_patient",
  "email": "alice@demo.com",
  "password": "Alice123!",
  "full_name": "Alice Johnson",
  "role": "PATIENT"
}
```

Password rules (enforced by the API):
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one digit
- At least one special character (`!@#$%^&*` etc.)

Role must be exactly `"PATIENT"` or `"DOCTOR"` (uppercase).

Successful response `201`:
```json
{
  "user_id": 1,
  "username": "alice_patient",
  "email": "alice@demo.com",
  "role": "PATIENT",
  "full_name": "Alice Johnson",
  "public_key_hash": "7f2a3b...",
  "public_key_compressed": "02a1b2c3...",
  "private_key_pem": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----",
  "private_key_qr": "data:image/png;base64,...",
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "warning_message": "⚠️ SAVE YOUR PRIVATE KEY IMMEDIATELY - It cannot be recovered if lost!",
  "created_at": "2025-02-18T10:00:00"
}
```

**Critical:** Save `private_key_pem` immediately. The server never stores it. If the user loses it they cannot grant access to anyone.

What to save after register:
```typescript
localStorage.setItem('access_token', data.access_token);
localStorage.setItem('user_id', String(data.user_id));
localStorage.setItem('role', data.role);
localStorage.setItem('full_name', data.full_name);
localStorage.setItem('public_key_compressed', data.public_key_compressed);

// PATIENTS ONLY — required to grant access later
if (data.role === 'PATIENT') {
  localStorage.setItem('private_key_pem', data.private_key_pem);
}
```

Also show the user a **download button** for the private key as a `.pem` file:

```typescript
function downloadPrivateKey(pem: string) {
  const blob = new Blob([pem], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'medledger-private-key.pem';
  a.click();
  URL.revokeObjectURL(url);
}
```

---

### Login

**POST** `/api/auth/login`

Request body:
```json
{
  "email": "alice@demo.com",
  "password": "Alice123!"
}
```

Note: login uses **email**, not username.

Successful response `200`:
```json
{
  "access_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user_id": 1,
  "username": "alice_patient",
  "email": "alice@demo.com",
  "role": "PATIENT",
  "full_name": "Alice Johnson",
  "public_key_hash": "7f2a3b..."
}
```

What to save after login:
```typescript
localStorage.setItem('access_token', data.access_token);
localStorage.setItem('user_id', String(data.user_id));
localStorage.setItem('role', data.role);
localStorage.setItem('full_name', data.full_name);
```

Note: login does **not** return the private key. The user must have already saved it at registration.

---

### Get Profile

**GET** `/api/auth/me`

Returns the current user's profile. Use this to verify the token is still valid on app load.

```typescript
async function checkAuth() {
  try {
    const response = await api.get('/api/auth/me');
    return response.data; // UserProfile
  } catch {
    return null; // Token expired or invalid
  }
}
```

---

## 6. Permission Flow

### Grant Access (Patient → Doctor)

**POST** `/permissions/grant`

The patient signs a permission with their private key. The doctor ID and patient ID must be **strings** (even though user_id is a number in the DB).

Request body:
```json
{
  "patient_id": "1",
  "doctor_id": "2",
  "record_id": "record-ecg-001",
  "time_window_hours": 2,
  "permission_level": "view_only",
  "patient_private_key_pem": "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----"
}
```

Fields:
- `patient_id` — string of the patient's user_id
- `doctor_id` — string of the doctor's user_id
- `record_id` — any string that identifies the record (you define this)
- `time_window_hours` — integer, how many hours the access is valid
- `permission_level` — `"view_only"` or `"full_access"`
- `patient_private_key_pem` — full PEM string including headers, with `\n` newlines

Successful response `200`:
```json
{
  "permission_id": "550e8400-e29b-41d4-a716-446655440000",
  "signature": "3045022100abc...",
  "patient_id": "1",
  "doctor_id": "2",
  "record_id": "record-ecg-001",
  "time_window": {
    "start": "2025-02-18T10:00:00",
    "end": "2025-02-18T12:00:00"
  },
  "permission_level": "view_only",
  "status": "granted"
}
```

Save the `permission_id` — the patient needs it to revoke access later.

---

### Verify Access (Doctor checks they have permission)

**POST** `/permissions/verify`

The doctor sends the patient's public key. The server checks the signature, revocation status, and time window.

Request body:
```json
{
  "doctor_id": "2",
  "record_id": "record-ecg-001",
  "patient_public_key_hex": "02a1b2c3..."
}
```

`patient_public_key_hex` is the `public_key_compressed` value from the patient's registration response. The patient must share this with the doctor (e.g. displayed in the UI after granting).

Response when allowed:
```json
{
  "allowed": true,
  "doctor_id": "2",
  "record_id": "record-ecg-001",
  "reason": "Access granted",
  "permission_id": "550e8400...",
  "timestamp": "2025-02-18T10:30:00"
}
```

Response when denied:
```json
{
  "allowed": false,
  "doctor_id": "2",
  "record_id": "record-ecg-001",
  "reason": "No active permission found for this doctor/record pair"
}
```

Possible denial reasons:
- `"No active permission found for this doctor/record pair"` — no grant exists or it was revoked
- `"Permission has expired"` — time window ended
- `"Signature verification failed"` — data was tampered with

---

### Revoke Access (Patient removes permission)

**POST** `/permissions/revoke`

Request body:
```json
{
  "permission_id": "550e8400-e29b-41d4-a716-446655440000",
  "patient_id": "1"
}
```

Successful response `200`:
```json
{
  "status": "revoked",
  "permission_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-02-18T11:00:00"
}
```

After this, any verify call for that permission will return `allowed: false`.

---

### List Permissions (Patient's active grants)

**GET** `/permissions/patient/{patient_id}`

```
GET /permissions/patient/1
```

Returns a list of all permissions the patient has granted:
```json
[
  {
    "permission_id": "550e8400...",
    "doctor_id": "2",
    "record_id": "record-ecg-001",
    "time_window": {
      "start": "2025-02-18T10:00:00",
      "end": "2025-02-18T12:00:00"
    },
    "is_revoked": false,
    "created_at": "2025-02-18T10:00:00"
  }
]
```

---

### Audit Log

**GET** `/permissions/audit`

Query params (all optional):
- `record_id` — filter by record
- `patient_id` — filter by patient
- `doctor_id` — filter by doctor
- `limit` — max entries (default 100)

```
GET /permissions/audit?limit=50
GET /permissions/audit?patient_id=1&limit=20
```

Returns:
```json
[
  {
    "timestamp": "2025-02-18T10:30:00",
    "action": "PERMISSION_GRANTED",
    "user_id": 1,
    "related_user_id": 2,
    "record_id": "record-ecg-001",
    "description": "...",
    "details": null
  }
]
```

Audit actions you'll see:
- `USER_REGISTERED`
- `LOGIN_SUCCESS`
- `LOGIN_FAILED`
- `PERMISSION_GRANTED`
- `PERMISSION_REVOKED`
- `RECORD_ACCESSED`

---

## 7. Storage Strategy

### What to store in localStorage

| Key | When set | Value |
|-----|----------|-------|
| `access_token` | Register / Login | JWT string |
| `user_id` | Register / Login | User's numeric ID as string |
| `role` | Register / Login | `"PATIENT"` or `"DOCTOR"` |
| `full_name` | Register / Login | Display name |
| `private_key_pem` | Register (PATIENT only) | Full PEM private key |
| `public_key_compressed` | Register | Patient's public key |

### Clear on logout

```typescript
function logout() {
  localStorage.clear();
  window.location.href = '/login';
}
```

### Private key warning UI

Always show a prominent warning to patients right after registration. The key should be:

1. Displayed in a `<textarea>` for copy-paste
2. Available as a downloadable `.pem` file
3. Shown as a QR code (the API returns `private_key_qr` as a base64 image)

```tsx
// Display QR code from the registration response
<img src={registrationResponse.private_key_qr} alt="Private key QR code" />
```

---

## 8. Full Code Examples

### AuthService

`src/services/auth.service.ts`

```typescript
import api from './api';

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  full_name: string;
  role: 'PATIENT' | 'DOCTOR';
}

export interface RegisterResponse {
  user_id: number;
  username: string;
  email: string;
  role: string;
  full_name: string;
  public_key_hash: string;
  public_key_compressed: string;
  private_key_pem: string;
  private_key_qr: string;
  access_token: string;
  expires_in: number;
  warning_message: string;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  user_id: number;
  username: string;
  email: string;
  role: string;
  full_name: string;
  public_key_hash: string;
}

export const AuthService = {
  async register(data: RegisterData): Promise<RegisterResponse> {
    const res = await api.post('/api/auth/register', data);
    return res.data;
  },

  async login(email: string, password: string): Promise<LoginResponse> {
    const res = await api.post('/api/auth/login', { email, password });
    return res.data;
  },

  async getProfile() {
    const res = await api.get('/api/auth/me');
    return res.data;
  },

  saveSession(data: RegisterResponse | LoginResponse) {
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('user_id', String(data.user_id));
    localStorage.setItem('role', data.role);
    localStorage.setItem('full_name', data.full_name);
    if ('public_key_compressed' in data && data.role === 'PATIENT') {
      localStorage.setItem('public_key_compressed', data.public_key_compressed);
    }
    if ('private_key_pem' in data && data.role === 'PATIENT') {
      localStorage.setItem('private_key_pem', data.private_key_pem);
    }
  },

  logout() {
    localStorage.clear();
    window.location.href = '/login';
  },

  isLoggedIn(): boolean {
    return !!localStorage.getItem('access_token');
  },

  getRole(): string | null {
    return localStorage.getItem('role');
  },

  getUserId(): string | null {
    return localStorage.getItem('user_id');
  },
};
```

---

### PermissionService

`src/services/permission.service.ts`

```typescript
import api from './api';

export const PermissionService = {
  async grant(
    doctorId: string,
    recordId: string,
    timeWindowHours: number,
    permissionLevel: 'view_only' | 'full_access' = 'view_only'
  ) {
    const privateKey = localStorage.getItem('private_key_pem');
    if (!privateKey) throw new Error('Private key not found. Did you save it at registration?');

    const res = await api.post('/permissions/grant', {
      patient_id: localStorage.getItem('user_id'),
      doctor_id: doctorId,
      record_id: recordId,
      time_window_hours: timeWindowHours,
      permission_level: permissionLevel,
      patient_private_key_pem: privateKey,
    });
    return res.data;
  },

  async verify(doctorId: string, recordId: string, patientPublicKeyHex: string) {
    const res = await api.post('/permissions/verify', {
      doctor_id: doctorId,
      record_id: recordId,
      patient_public_key_hex: patientPublicKeyHex,
    });
    return res.data; // { allowed: boolean, reason: string, ... }
  },

  async revoke(permissionId: string) {
    const res = await api.post('/permissions/revoke', {
      permission_id: permissionId,
      patient_id: localStorage.getItem('user_id'),
    });
    return res.data;
  },

  async listMyPermissions() {
    const userId = localStorage.getItem('user_id');
    const res = await api.get(`/permissions/patient/${userId}`);
    return res.data;
  },

  async getAuditLog(filters: { record_id?: string; patient_id?: string; doctor_id?: string; limit?: number } = {}) {
    const params = new URLSearchParams();
    if (filters.record_id) params.set('record_id', filters.record_id);
    if (filters.patient_id) params.set('patient_id', filters.patient_id);
    if (filters.doctor_id) params.set('doctor_id', filters.doctor_id);
    if (filters.limit) params.set('limit', String(filters.limit));
    const res = await api.get(`/permissions/audit?${params}`);
    return res.data;
  },
};
```

---

### Register Page

`src/pages/Register.tsx`

```tsx
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthService } from '../services/auth.service';

export default function Register() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    username: '', email: '', password: '', full_name: '', role: 'PATIENT' as 'PATIENT' | 'DOCTOR'
  });
  const [privateKey, setPrivateKey] = useState('');
  const [qrCode, setQrCode] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const set = (field: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm(f => ({ ...f, [field]: e.target.value }));

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      const data = await AuthService.register(form);
      AuthService.saveSession(data);
      setPrivateKey(data.private_key_pem);
      setQrCode(data.private_key_qr);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  }

  function downloadKey() {
    const blob = new Blob([privateKey], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'medledger-private-key.pem';
    a.click();
  }

  // Step 2: Show private key warning before proceeding
  if (privateKey) {
    return (
      <div className="max-w-lg mx-auto p-6">
        <div className="bg-yellow-50 border-2 border-yellow-400 rounded-lg p-6 mb-6">
          <h2 className="text-xl font-bold text-yellow-800 mb-2">⚠️ Save Your Private Key</h2>
          <p className="text-yellow-700 text-sm mb-4">
            This is the only copy. The server does not store it.
            If you lose it, you cannot grant doctors access to your records.
          </p>
          {form.role === 'PATIENT' && (
            <>
              <textarea
                readOnly
                value={privateKey}
                className="w-full h-32 font-mono text-xs border rounded p-2 bg-white mb-3"
              />
              <div className="flex gap-3">
                <button onClick={downloadKey}
                  className="flex-1 bg-yellow-500 text-white py-2 rounded hover:bg-yellow-600">
                  Download .pem file
                </button>
              </div>
              {qrCode && (
                <div className="mt-4 text-center">
                  <p className="text-sm text-yellow-700 mb-2">Or scan QR code for offline backup:</p>
                  <img src={qrCode} alt="Private key QR" className="mx-auto w-40 h-40" />
                </div>
              )}
            </>
          )}
        </div>
        <button onClick={() => navigate('/dashboard')}
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700">
          I've saved my key — Continue to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-lg mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">Create Account</h1>
      {error && <div className="bg-red-50 text-red-600 p-3 rounded mb-4">{error}</div>}
      <form onSubmit={handleSubmit} className="space-y-4">
        <input placeholder="Full Name" value={form.full_name} onChange={set('full_name')}
          className="w-full border rounded px-3 py-2" required />
        <input placeholder="Username" value={form.username} onChange={set('username')}
          className="w-full border rounded px-3 py-2" required />
        <input type="email" placeholder="Email" value={form.email} onChange={set('email')}
          className="w-full border rounded px-3 py-2" required />
        <input type="password" placeholder="Password (min 8 chars, upper+lower+digit+special)"
          value={form.password} onChange={set('password')}
          className="w-full border rounded px-3 py-2" required />
        <select value={form.role} onChange={set('role')} className="w-full border rounded px-3 py-2">
          <option value="PATIENT">Patient</option>
          <option value="DOCTOR">Doctor</option>
        </select>
        <button type="submit" disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50">
          {loading ? 'Creating account...' : 'Register'}
        </button>
      </form>
    </div>
  );
}
```

---

### Grant Access Page (Patient)

`src/pages/GrantAccess.tsx`

```tsx
import { useState } from 'react';
import { PermissionService } from '../services/permission.service';

export default function GrantAccess() {
  const [form, setForm] = useState({
    doctorId: '', recordId: '', hours: '2', level: 'view_only'
  });
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const privateKey = localStorage.getItem('private_key_pem');

  async function handleGrant(e: React.FormEvent) {
    e.preventDefault();
    setError(''); setResult(null); setLoading(true);
    try {
      const data = await PermissionService.grant(
        form.doctorId, form.recordId, parseInt(form.hours), form.level as any
      );
      setResult(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  }

  if (!privateKey) {
    return (
      <div className="max-w-lg mx-auto p-6">
        <div className="bg-red-50 border border-red-300 rounded p-4">
          <p className="text-red-700 font-medium">Private key not found in browser storage.</p>
          <p className="text-red-600 text-sm mt-1">
            You need to re-upload your .pem file or re-register to grant access.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-lg mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">Grant Doctor Access</h1>

      {error && <div className="bg-red-50 text-red-600 p-3 rounded mb-4">{error}</div>}
      {result && (
        <div className="bg-green-50 border border-green-300 rounded p-4 mb-4">
          <p className="text-green-700 font-medium">✓ Access granted!</p>
          <p className="text-sm text-green-600 mt-1">Permission ID: {result.permission_id}</p>
          <p className="text-sm text-green-600">Valid until: {new Date(result.time_window.end).toLocaleString()}</p>
          <p className="text-sm text-green-600 mt-2">
            Share your public key with the doctor so they can verify:
          </p>
          <code className="text-xs break-all bg-white border rounded p-2 block mt-1">
            {localStorage.getItem('public_key_compressed')}
          </code>
        </div>
      )}

      <form onSubmit={handleGrant} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Doctor's User ID</label>
          <input value={form.doctorId} onChange={e => setForm(f => ({...f, doctorId: e.target.value}))}
            placeholder="e.g. 2" className="w-full border rounded px-3 py-2" required />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Record ID</label>
          <input value={form.recordId} onChange={e => setForm(f => ({...f, recordId: e.target.value}))}
            placeholder="e.g. record-ecg-001" className="w-full border rounded px-3 py-2" required />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Access Duration (hours)</label>
          <input type="number" min="1" max="72" value={form.hours}
            onChange={e => setForm(f => ({...f, hours: e.target.value}))}
            className="w-full border rounded px-3 py-2" required />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Permission Level</label>
          <select value={form.level} onChange={e => setForm(f => ({...f, level: e.target.value}))}
            className="w-full border rounded px-3 py-2">
            <option value="view_only">View Only</option>
            <option value="full_access">Full Access</option>
          </select>
        </div>
        <button type="submit" disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50">
          {loading ? 'Signing & granting...' : 'Grant Access'}
        </button>
      </form>
    </div>
  );
}
```

---

### Verify Access Page (Doctor)

`src/pages/VerifyAccess.tsx`

```tsx
import { useState } from 'react';
import { PermissionService } from '../services/permission.service';

export default function VerifyAccess() {
  const [recordId, setRecordId] = useState('');
  const [patientPublicKey, setPatientPublicKey] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  async function handleVerify(e: React.FormEvent) {
    e.preventDefault();
    setResult(null); setLoading(true);
    try {
      const data = await PermissionService.verify(
        localStorage.getItem('user_id')!,
        recordId,
        patientPublicKey
      );
      setResult(data);
    } catch (err: any) {
      setResult({ allowed: false, reason: err.response?.data?.detail || err.message });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-lg mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">Verify Record Access</h1>

      {result && (
        <div className={`p-4 rounded mb-4 border ${
          result.allowed ? 'bg-green-50 border-green-300' : 'bg-red-50 border-red-300'
        }`}>
          <p className={`font-bold ${result.allowed ? 'text-green-700' : 'text-red-700'}`}>
            {result.allowed ? '✓ ACCESS GRANTED' : '✗ ACCESS DENIED'}
          </p>
          <p className={`text-sm mt-1 ${result.allowed ? 'text-green-600' : 'text-red-600'}`}>
            {result.reason}
          </p>
        </div>
      )}

      <form onSubmit={handleVerify} className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Record ID</label>
          <input value={recordId} onChange={e => setRecordId(e.target.value)}
            placeholder="e.g. record-ecg-001" className="w-full border rounded px-3 py-2" required />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Patient's Public Key</label>
          <textarea value={patientPublicKey} onChange={e => setPatientPublicKey(e.target.value)}
            placeholder="02a1b2c3... (patient shares this with you)"
            className="w-full border rounded px-3 py-2 font-mono text-xs h-20" required />
          <p className="text-xs text-gray-500 mt-1">
            The patient will share this compressed public key after granting access.
          </p>
        </div>
        <button type="submit" disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 disabled:opacity-50">
          {loading ? 'Verifying...' : 'Verify Access'}
        </button>
      </form>
    </div>
  );
}
```

---

## 9. Role-Based UI

After login, redirect users based on their role:

```typescript
// In your login handler:
const role = data.role; // "PATIENT" or "DOCTOR"
if (role === 'PATIENT') {
  navigate('/patient/dashboard');
} else if (role === 'DOCTOR') {
  navigate('/doctor/dashboard');
}
```

Show/hide UI elements by role:

```tsx
const role = localStorage.getItem('role');

{role === 'PATIENT' && (
  <nav>
    <Link to="/grant-access">Grant Access</Link>
    <Link to="/my-permissions">My Permissions</Link>
  </nav>
)}

{role === 'DOCTOR' && (
  <nav>
    <Link to="/verify-access">Verify Access</Link>
    <Link to="/my-access-log">Access Log</Link>
  </nav>
)}
```

Protect routes:

```tsx
function PatientOnlyRoute({ element }: { element: JSX.Element }) {
  const role = localStorage.getItem('role');
  if (!localStorage.getItem('access_token')) return <Navigate to="/login" />;
  if (role !== 'PATIENT') return <Navigate to="/dashboard" />;
  return element;
}
```

---

## 10. Error Handling

### Common API errors

| HTTP Status | When it happens | What to show |
|-------------|-----------------|--------------|
| 400 | Invalid request data | Show `error.response.data.detail` |
| 401 | Token expired or missing | Redirect to login |
| 409 | Email/username already registered | "An account with this email already exists" |
| 422 | Validation error (e.g. weak password) | Show field-level errors from `error.response.data.detail` |
| 500 | Server error | "Something went wrong. Please try again." |

### Extracting error messages

```typescript
function getErrorMessage(err: any): string {
  const detail = err.response?.data?.detail;
  if (!detail) return 'An unexpected error occurred.';
  // detail can be a string or an array of validation errors
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail.map((e: any) => `${e.loc?.join('.')}: ${e.msg}`).join(', ');
  }
  return String(detail);
}
```

### Private key missing

This is the most common user error for patients. Always check before any grant operation:

```typescript
const key = localStorage.getItem('private_key_pem');
if (!key) {
  // Don't let them reach the grant form at all
  // Show an upload prompt instead
}
```

Provide a way for users to re-upload their `.pem` file:

```tsx
function UploadPrivateKey() {
  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result as string;
      if (content.includes('PRIVATE KEY')) {
        localStorage.setItem('private_key_pem', content);
        alert('Private key loaded.');
      } else {
        alert('Invalid file. Expected a .pem file.');
      }
    };
    reader.readAsText(file);
  }

  return (
    <div>
      <p>Upload your private key (.pem file) to grant access:</p>
      <input type="file" accept=".pem,.txt" onChange={handleFile} />
    </div>
  );
}
```

---

## 11. Troubleshooting

### CORS error in browser console

The API only allows specific origins. Add yours before starting the backend:

```bash
export ALLOWED_ORIGINS="http://localhost:5173,http://localhost:3000"
uvicorn src.api.main:app --reload --port 8000
```

### "Failed to fetch" / network error

Check the backend is running:
```bash
curl http://localhost:8000/health
```

Check your `.env` file has the correct URL:
```
VITE_API_URL=http://localhost:8000
```

### 422 Unprocessable Entity on register

Password doesn't meet requirements. All of these must be true:
- At least 8 characters
- At least one uppercase letter (`A-Z`)
- At least one lowercase letter (`a-z`)
- At least one digit (`0-9`)
- At least one special character (`!@#$%^&*()_+-=[]{}` etc.)

### Grant fails with "Invalid private key format"

The PEM string must have actual newlines, not `\n` literals:

```typescript
// Wrong — this won't work
const key = "-----BEGIN EC PRIVATE KEY-----\\nMIGE...\\n-----END EC PRIVATE KEY-----";

// Correct — real newlines
const key = localStorage.getItem('private_key_pem'); // stored correctly from registration
```

### Verify returns `allowed: false` with reason "No active permission"

Check that:
1. The grant was called with the correct `doctor_id` (as a string matching user_id)
2. The `record_id` in verify matches exactly what was used in grant
3. The permission hasn't expired — check `time_window.end`
4. The permission wasn't revoked

### Token expires (1 hour default)

The token expires after 1 hour. When it does, the interceptor in `api.ts` will clear localStorage and redirect to `/login`. On the login page, remind patients to have their private key file ready.

---

## Quick Reference

```
Register    POST /api/auth/register    → save token + private_key_pem
Login       POST /api/auth/login       → save token
Profile     GET  /api/auth/me          → verify token still valid

Grant       POST /permissions/grant    → needs private_key_pem
Verify      POST /permissions/verify   → needs patient's public_key_compressed
Revoke      POST /permissions/revoke   → needs permission_id
List        GET  /permissions/patient/{id}
Audit       GET  /permissions/audit

All IDs:  pass as strings ("1", not 1)
Auth:     Authorization: Bearer <token>
CORS:     set ALLOWED_ORIGINS env var to match your frontend port
```
