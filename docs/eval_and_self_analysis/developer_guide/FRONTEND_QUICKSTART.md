# MedLedger Frontend Quick Start Guide
## Build a Patient-Controlled Healthcare App

---

## OVERVIEW

MedLedger frontend is a **React application** where:
- **Patients** control who accesses their medical records
- **Doctors** request access and view records
- **Everyone** sees an immutable audit trail

This guide shows you how to build a working frontend in **Round 2** of the hackathon.

---

## TECH STACK

```
Frontend Framework:   React 18+ with TypeScript
State Management:     TanStack Query (React Query) or Redux
UI Components:        Tailwind CSS + Shadcn/UI or Material-UI
HTTP Client:         Axios or Fetch API
Authentication:      JWT (from backend)
Routing:             React Router v6
Build Tool:          Vite or Create React App
Testing:             Jest + React Testing Library
```

---

## PROJECT STRUCTURE (Recommended)

```
frontend/
├── src/
│   ├── components/
│   │   ├── Auth/
│   │   │   ├── Login.tsx
│   │   │   ├── Register.tsx
│   │   │   └── PrivateRoute.tsx
│   │   ├── Dashboard/
│   │   │   ├── PatientDashboard.tsx
│   │   │   ├── DoctorDashboard.tsx
│   │   │   └── AdminDashboard.tsx
│   │   ├── Permissions/
│   │   │   ├── GrantAccess.tsx
│   │   │   ├── AccessRequests.tsx
│   │   │   ├── RevokeAccess.tsx
│   │   │   └── PermissionList.tsx
│   │   ├── Records/
│   │   │   ├── RecordUpload.tsx
│   │   │   ├── RecordView.tsx
│   │   │   └── RecordList.tsx
│   │   ├── Audit/
│   │   │   ├── AuditTrail.tsx
│   │   │   └── AuditLog.tsx
│   │   ├── Common/
│   │   │   ├── Header.tsx
│   │   │   ├── Sidebar.tsx
│   │   │   ├── Footer.tsx
│   │   │   └── LoadingSpinner.tsx
│   │   └── Layout.tsx
│   ├── services/
│   │   ├── api.ts              # API client configuration
│   │   ├── auth.service.ts     # Authentication endpoints
│   │   ├── permission.service.ts
│   │   ├── record.service.ts
│   │   └── audit.service.ts
│   ├── hooks/
│   │   ├── useAuth.ts
│   │   ├── usePermissions.ts
│   │   ├── useRecords.ts
│   │   └── useAudit.ts
│   ├── types/
│   │   ├── auth.ts
│   │   ├── permission.ts
│   │   ├── record.ts
│   │   └── audit.ts
│   ├── pages/
│   │   ├── Home.tsx
│   │   ├── Login.tsx
│   │   ├── Dashboard.tsx
│   │   ├── Records.tsx
│   │   ├── Permissions.tsx
│   │   ├── Audit.tsx
│   │   └── NotFound.tsx
│   ├── utils/
│   │   ├── crypto.ts           # Client-side crypto utilities
│   │   ├── date.ts
│   │   └── format.ts
│   ├── context/
│   │   └── AuthContext.tsx
│   ├── store/                  # Redux (if using)
│   │   ├── slices/
│   │   ├── hooks.ts
│   │   └── store.ts
│   ├── App.tsx
│   ├── App.css
│   ├── index.tsx
│   └── index.css
├── public/
│   └── index.html
├── .env.example
├── .env
├── package.json
├── tsconfig.json
├── vite.config.ts (or webpack.config.js)
└── README.md
```

---

## SETUP (5 Minutes)

### Step 1: Create React App
```bash
# Option 1: Vite (faster, modern)
npm create vite@latest medledger-frontend -- --template react-ts
cd medledger-frontend
npm install

# Option 2: Create React App
npx create-react-app medledger-frontend --template typescript
cd medledger-frontend
```

### Step 2: Install Dependencies
```bash
npm install axios react-router-dom
npm install -D tailwindcss postcss autoprefixer
npm install @shadcn/ui             # Optional UI components
npm install @tanstack/react-query   # For data fetching
npm install zustand                 # Light state management (or Redux)
```

### Step 3: Setup Environment
Create `.env` file:
```
VITE_API_URL=http://localhost:8000
VITE_API_TIMEOUT=30000
VITE_DEBUG=true
```

### Step 4: Configure Axios
Create `src/services/api.ts`:
```typescript
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: parseInt(import.meta.env.VITE_API_TIMEOUT || '30000'),
});

// Add JWT token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 (token expired)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
```

### Step 5: Start Development Server
```bash
npm run dev
```

Open: **http://localhost:5173**

---

## KEY PAGES TO BUILD (Priority Order)

### 1. **Login Page** (1 hour)
```typescript
// src/pages/Login.tsx
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await api.post('/auth/login', {
        username,
        password,
      });
      
      localStorage.setItem('access_token', response.data.access_token);
      localStorage.setItem('user_id', response.data.user_id);
      localStorage.setItem('role', response.data.role);
      
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <h2 className="text-center text-3xl font-bold">MedLedger</h2>
        <form onSubmit={handleLogin} className="space-y-6">
          {error && <div className="text-red-500 text-sm">{error}</div>}
          
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-4 py-2 border rounded-lg"
            required
          />
          
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-4 py-2 border rounded-lg"
            required
          />
          
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
}
```

### 2. **Patient Dashboard** (2 hours)
```typescript
// src/pages/Dashboard.tsx
import { useEffect, useState } from 'react';
import api from '../services/api';

interface MedicalRecord {
  id: string;
  name: string;
  createdAt: string;
  accessCount: number;
}

export default function PatientDashboard() {
  const [records, setRecords] = useState<MedicalRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchRecords = async () => {
      try {
        const response = await api.get('/records/patient');
        setRecords(response.data);
      } catch (error) {
        console.error('Failed to fetch records:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchRecords();
  }, []);

  if (loading) return <div>Loading...</div>;

  return (
    <div className="max-w-6xl mx-auto p-4">
      <h1 className="text-3xl font-bold mb-8">My Medical Records</h1>
      
      <div className="grid gap-4 mb-8">
        {records.map((record) => (
          <div key={record.id} className="border rounded-lg p-4 hover:shadow-lg">
            <h3 className="font-semibold">{record.name}</h3>
            <p className="text-sm text-gray-600">
              Created: {new Date(record.createdAt).toLocaleDateString()}
            </p>
            <p className="text-sm text-gray-600">
              Access count: {record.accessCount}
            </p>
            <button
              onClick={() => window.location.href = `/records/${record.id}`}
              className="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              View
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
```

### 3. **Grant Access Page** (2 hours)
```typescript
// src/pages/GrantAccess.tsx
import { useState } from 'react';
import api from '../services/api';

export default function GrantAccess() {
  const [doctorId, setDoctorId] = useState('');
  const [recordId, setRecordId] = useState('');
  const [hours, setHours] = useState(2);
  const [permissionLevel, setPermissionLevel] = useState('view_only');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');

  const handleGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      // Get private key from localStorage (user saves it on registration)
      const privateKey = localStorage.getItem('private_key_pem');
      if (!privateKey) {
        alert('Private key not found. Please register again.');
        return;
      }

      const response = await api.post('/permissions/grant', {
        patient_id: localStorage.getItem('user_id'),
        doctor_id: doctorId,
        record_id: recordId,
        time_window_hours: hours,
        permission_level: permissionLevel,
        patient_private_key_pem: privateKey,
      });

      setSuccess(`Access granted! Signature: ${response.data.signature.substring(0, 20)}...`);
      
      // Reset form
      setDoctorId('');
      setRecordId('');
      setHours(2);
      setPermissionLevel('view_only');
    } catch (error: any) {
      alert(error.response?.data?.detail || 'Failed to grant access');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-4">
      <h1 className="text-3xl font-bold mb-8">Grant Access to Doctor</h1>
      
      {success && (
        <div className="mb-4 p-4 bg-green-100 text-green-700 rounded">
          ✓ {success}
        </div>
      )}

      <form onSubmit={handleGrant} className="space-y-6">
        <div>
          <label className="block text-sm font-medium mb-2">Doctor ID</label>
          <input
            type="text"
            value={doctorId}
            onChange={(e) => setDoctorId(e.target.value)}
            className="w-full px-4 py-2 border rounded-lg"
            placeholder="doctor-uuid-here"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">Record ID</label>
          <input
            type="text"
            value={recordId}
            onChange={(e) => setRecordId(e.target.value)}
            className="w-full px-4 py-2 border rounded-lg"
            placeholder="record-uuid-here"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">
            Access Duration (hours)
          </label>
          <input
            type="number"
            min="1"
            max="72"
            value={hours}
            onChange={(e) => setHours(parseInt(e.target.value))}
            className="w-full px-4 py-2 border rounded-lg"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-2">Permission Level</label>
          <select
            value={permissionLevel}
            onChange={(e) => setPermissionLevel(e.target.value)}
            className="w-full px-4 py-2 border rounded-lg"
          >
            <option value="view_only">View Only</option>
            <option value="view_download">View & Download</option>
          </select>
        </div>

        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <p className="text-sm text-blue-700">
            <strong>This will be signed with your private key.</strong> The doctor will need this signature to verify they have your permission.
          </p>
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Granting access...' : 'Grant Access'}
        </button>
      </form>
    </div>
  );
}
```

### 4. **Audit Trail Page** (1.5 hours)
```typescript
// src/pages/Audit.tsx
import { useEffect, useState } from 'react';
import api from '../services/api';

interface AuditEntry {
  timestamp: string;
  action: string;
  doctor_id: string;
  patient_id: string;
  record_id: string;
  details: string;
}

export default function AuditTrail() {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await api.get('/permissions/audit');
        setLogs(response.data);
      } catch (error) {
        console.error('Failed to fetch audit logs:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchLogs();
  }, []);

  if (loading) return <div>Loading audit trail...</div>;

  return (
    <div className="max-w-6xl mx-auto p-4">
      <h1 className="text-3xl font-bold mb-8">Immutable Audit Trail</h1>
      <p className="text-gray-600 mb-8">
        Every access attempt is logged and cannot be deleted. This proves what happened.
      </p>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <thead>
            <tr className="bg-gray-100">
              <th className="border p-2 text-left">Timestamp</th>
              <th className="border p-2 text-left">Action</th>
              <th className="border p-2 text-left">Doctor</th>
              <th className="border p-2 text-left">Record</th>
              <th className="border p-2 text-left">Details</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log, idx) => (
              <tr key={idx} className="hover:bg-gray-50">
                <td className="border p-2 text-sm">
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td className="border p-2 text-sm font-semibold">
                  {log.action}
                </td>
                <td className="border p-2 text-sm">{log.doctor_id || '-'}</td>
                <td className="border p-2 text-sm">{log.record_id || '-'}</td>
                <td className="border p-2 text-sm text-gray-600">{log.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
```

---

## CUSTOM HOOKS (Simplify Components)

### useAuth Hook
```typescript
// src/hooks/useAuth.ts
import { useState, useEffect } from 'react';
import api from '../services/api';

interface User {
  id: string;
  username: string;
  role: 'PATIENT' | 'DOCTOR' | 'ADMIN';
  public_key_hash: string;
}

export const useAuth = () => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      // Verify token is still valid
      api
        .get('/auth/me')
        .then((response) => {
          setUser(response.data);
          setIsAuthenticated(true);
        })
        .catch(() => {
          localStorage.removeItem('access_token');
          setIsAuthenticated(false);
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_id');
    localStorage.removeItem('role');
    localStorage.removeItem('private_key_pem');
    setUser(null);
    setIsAuthenticated(false);
  };

  return { user, loading, isAuthenticated, logout };
};
```

### usePermissions Hook
```typescript
// src/hooks/usePermissions.ts
import { useState } from 'react';
import api from '../services/api';

export const usePermissions = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const grantPermission = async (
    doctorId: string,
    recordId: string,
    hours: number,
    privateKeyPem: string
  ) => {
    setLoading(true);
    setError(null);

    try {
      const response = await api.post('/permissions/grant', {
        patient_id: localStorage.getItem('user_id'),
        doctor_id: doctorId,
        record_id: recordId,
        time_window_hours: hours,
        permission_level: 'view_only',
        patient_private_key_pem: privateKeyPem,
      });

      return response.data;
    } catch (err: any) {
      const message = err.response?.data?.detail || 'Failed to grant permission';
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const verifyPermission = async (
    doctorId: string,
    recordId: string,
    patientPublicKeyHex: string
  ) => {
    setLoading(true);
    setError(null);

    try {
      const response = await api.post('/permissions/verify', {
        doctor_id: doctorId,
        record_id: recordId,
        patient_public_key_hex: patientPublicKeyHex,
      });

      return response.data;
    } catch (err: any) {
      const message = err.response?.data?.detail || 'Failed to verify permission';
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const revokePermission = async (permissionId: string) => {
    setLoading(true);
    setError(null);

    try {
      const response = await api.post('/permissions/revoke', {
        permission_id: permissionId,
        patient_id: localStorage.getItem('user_id'),
      });

      return response.data;
    } catch (err: any) {
      const message = err.response?.data?.detail || 'Failed to revoke permission';
      setError(message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { grantPermission, verifyPermission, revokePermission, loading, error };
};
```

---

## STYLING WITH TAILWIND

### Setup Tailwind
```bash
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init -p
```

### tailwind.config.js
```javascript
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
```

### src/index.css
```css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Custom MedLedger styles */
:root {
  --primary: #2563eb;  /* Blue */
  --success: #10b981; /* Green */
  --danger: #ef4444;  /* Red */
  --warning: #f59e0b; /* Amber */
}

body {
  @apply bg-gray-50 text-gray-900;
}

.btn-primary {
  @apply px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition;
}

.card {
  @apply bg-white rounded-lg shadow hover:shadow-lg transition p-4;
}
```

---

## ROUTING SETUP

### App.tsx
```typescript
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './hooks/useAuth';

// Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import GrantAccess from './pages/GrantAccess';
import AuditTrail from './pages/Audit';

// Protected Route Component
function PrivateRoute({ element }: { element: JSX.Element }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) return <div>Loading...</div>;
  return isAuthenticated ? element : <Navigate to="/login" />;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route 
          path="/dashboard" 
          element={<PrivateRoute element={<Dashboard />} />} 
        />
        <Route 
          path="/grant-access" 
          element={<PrivateRoute element={<GrantAccess />} />} 
        />
        <Route 
          path="/audit" 
          element={<PrivateRoute element={<AuditTrail />} />} 
        />
        <Route path="/" element={<Navigate to="/dashboard" />} />
      </Routes>
    </BrowserRouter>
  );
}
```

---

## BUILD & DEPLOY

### Development
```bash
npm run dev
```

### Production Build
```bash
npm run build
npm run preview
```

### Deploy to Vercel (Free)
```bash
npm install -g vercel
vercel
```

---

## KEY FEATURES TO IMPLEMENT

- [ ] User registration (save private key securely)
- [ ] Login with JWT
- [ ] Patient grants access (with signature)
- [ ] Doctor requests access
- [ ] Verify access via API
- [ ] View audit trail
- [ ] Revoke access (one-click)
- [ ] Display time window remaining
- [ ] Show access was denied (for admin attempt)
- [ ] Responsive design (mobile-friendly)

---

## TESTING WITH MOCK API

```typescript
// src/services/api.ts - Add mock data for testing
if (import.meta.env.VITE_DEBUG === 'true') {
  api.interceptors.response.use((response) => {
    console.log('API Response:', response);
    return response;
  });
}
```

---

## TIPS FOR HACKATHON

1. **Use a UI component library** (Shadcn/UI, Material-UI) to save time
2. **Focus on core flows** (auth → grant → verify → audit)
3. **Make it look polished** (judges care about UX)
4. **Test with actual backend** (use your FastAPI server)
5. **Handle errors gracefully** (show user-friendly messages)
6. **Add loading states** (show spinners during API calls)
7. **Keep it simple** (don't over-engineer)

---

## NEXT STEPS

1. Create React app with Vite (5 min)
2. Setup Tailwind CSS (5 min)
3. Create Login page (1 hour)
4. Create Dashboard (1 hour)
5. Create Grant Access page (2 hours)
6. Create Audit Trail (1.5 hours)
7. Connect to backend API (2 hours)
8. Test end-to-end (2 hours)

**Total: ~10 hours** for a working frontend!

---

**Ready to build the UI that shows judges how amazing MedLedger is?** Let's go! 🎨
