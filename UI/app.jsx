
// MedLedger React UI
// Served from UI/ — talks to FastAPI on http://localhost:8000
// Uses React 18 UMD + Babel standalone (no bundler required for dev)

const { useState, useEffect, useCallback, useRef } = React;
const { createRoot } = ReactDOM;

// ─── API layer ────────────────────────────────────────────────────────────────

const BASE = "http://localhost:8000";

async function api(method, path, body, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({ detail: r.statusText }));
  if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
  return data;
}

const Auth = {
  register: (b) => api("POST", "/api/auth/register", b),
  verify:   (token) => api("POST", "/api/auth/verify", { token }),
  login:    (b) => api("POST", "/api/auth/login", b),
  me:       (t) => api("GET", "/api/auth/me", null, t),
};

const Vault = {
  upload:      (b, t) => api("POST", "/api/vault/upload", b, t),
  download:    (id, b, t) => api("POST", `/api/vault/download/${id}`, b, t),
  records:     (t) => api("GET", "/api/vault/records", null, t),
  grant:       (b, t) => api("POST", "/api/vault/grant", b, t),
  revoke:      (b, t) => api("POST", "/api/vault/revoke", b, t),
  permissions: (b, t) => api("POST", "/api/vault/permissions", b, t),
  inbox:       (b, t) => api("POST", "/api/vault/inbox", b, t),
  rotateKey:   (b, t) => api("POST", "/api/vault/rotate-key", b, t),
};

// ─── Session helpers ──────────────────────────────────────────────────────────

const Session = {
  save(data) { sessionStorage.setItem("ml_session", JSON.stringify(data)); },
  load() {
    try { return JSON.parse(sessionStorage.getItem("ml_session") || "null"); }
    catch { return null; }
  },
  clear() { sessionStorage.removeItem("ml_session"); },
};

// hex helpers
const toHex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const fromHex = (hex) => new Uint8Array(hex.match(/.{2}/g).map(b => parseInt(b, 16)));

// ─── Design tokens ────────────────────────────────────────────────────────────

const css = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Mono:wght@400;500&family=Outfit:wght@300;400;500;600&display=swap');

  :root {
    --ink:       #0f1923;
    --ink-2:     #374151;
    --ink-3:     #6b7280;
    --surface:   #ffffff;
    --surface-2: #f8f9fb;
    --surface-3: #f1f4f8;
    --border:    #e5e9f0;
    --accent:    #1d6fdb;
    --accent-2:  #1558b8;
    --accent-bg: #eef4ff;
    --success:   #16a34a;
    --success-bg:#dcfce7;
    --danger:    #dc2626;
    --danger-bg: #fee2e2;
    --warn:      #d97706;
    --warn-bg:   #fef3c7;
    --shadow-sm: 0 1px 3px rgba(0,0,0,.06), 0 1px 2px rgba(0,0,0,.04);
    --shadow-md: 0 4px 12px rgba(0,0,0,.08), 0 2px 4px rgba(0,0,0,.04);
    --shadow-lg: 0 12px 32px rgba(0,0,0,.10), 0 4px 8px rgba(0,0,0,.06);
    --r:         12px;
    --r-lg:      18px;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Outfit', sans-serif;
    font-size: 15px;
    line-height: 1.6;
    color: var(--ink);
    background: var(--surface-2);
    min-height: 100vh;
  }

  /* ── Layout ── */
  .app { display: flex; min-height: 100vh; }

  .sidebar {
    width: 240px;
    flex-shrink: 0;
    background: var(--ink);
    color: #fff;
    display: flex;
    flex-direction: column;
    padding: 0;
    position: fixed;
    top: 0; left: 0; bottom: 0;
    z-index: 50;
  }

  .sidebar-logo {
    padding: 28px 24px 20px;
    border-bottom: 1px solid rgba(255,255,255,.08);
  }

  .sidebar-logo h1 {
    font-family: 'DM Serif Display', serif;
    font-size: 22px;
    letter-spacing: -.3px;
    color: #fff;
  }

  .sidebar-logo span {
    font-family: 'DM Mono', monospace;
    font-size: 10px;
    color: rgba(255,255,255,.4);
    letter-spacing: 1.5px;
    text-transform: uppercase;
  }

  .sidebar-nav { flex: 1; padding: 16px 12px; overflow-y: auto; }

  .nav-section { margin-bottom: 24px; }
  .nav-label {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: rgba(255,255,255,.3);
    padding: 0 12px;
    margin-bottom: 6px;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 12px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 400;
    color: rgba(255,255,255,.6);
    transition: all .15s;
    border: none;
    background: none;
    width: 100%;
    text-align: left;
  }

  .nav-item:hover { background: rgba(255,255,255,.07); color: #fff; }
  .nav-item.active { background: rgba(255,255,255,.12); color: #fff; font-weight: 500; }
  .nav-item .icon { font-size: 16px; width: 20px; text-align: center; opacity: .8; }

  .sidebar-footer {
    padding: 16px 12px;
    border-top: 1px solid rgba(255,255,255,.08);
  }

  .user-chip {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 8px;
    background: rgba(255,255,255,.06);
  }

  .user-avatar {
    width: 32px; height: 32px;
    border-radius: 50%;
    background: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    font-size: 13px;
    color: #fff;
    flex-shrink: 0;
  }

  .user-info { flex: 1; min-width: 0; }
  .user-name { font-size: 13px; font-weight: 500; color: #fff; truncate: ellipsis; overflow: hidden; white-space: nowrap; }
  .user-role { font-size: 11px; color: rgba(255,255,255,.35); }

  .main {
    margin-left: 240px;
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  .topbar {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 32px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 40;
  }

  .page-title { font-size: 16px; font-weight: 600; color: var(--ink); }
  .page-subtitle { font-size: 13px; color: var(--ink-3); margin-top: 1px; }

  .content { padding: 28px 32px; flex: 1; }

  /* ── Auth pages ── */
  .auth-wrap {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--ink);
    padding: 24px;
  }

  .auth-card {
    width: 100%;
    max-width: 420px;
    background: var(--surface);
    border-radius: var(--r-lg);
    padding: 40px;
    box-shadow: var(--shadow-lg);
  }

  .auth-logo {
    text-align: center;
    margin-bottom: 32px;
  }

  .auth-logo h1 {
    font-family: 'DM Serif Display', serif;
    font-size: 30px;
    color: var(--ink);
  }

  .auth-logo p {
    font-size: 13px;
    color: var(--ink-3);
    margin-top: 4px;
  }

  .auth-tabs {
    display: flex;
    border-bottom: 1px solid var(--border);
    margin-bottom: 28px;
  }

  .auth-tab {
    flex: 1;
    padding: 10px;
    text-align: center;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border: none;
    background: none;
    color: var(--ink-3);
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    transition: all .15s;
  }

  .auth-tab.active { color: var(--accent); border-bottom-color: var(--accent); }

  /* ── Form elements ── */
  .field { margin-bottom: 16px; }
  .field label { display: block; font-size: 13px; font-weight: 500; color: var(--ink-2); margin-bottom: 6px; }

  .input, .select, .textarea {
    width: 100%;
    padding: 10px 14px;
    border: 1.5px solid var(--border);
    border-radius: var(--r);
    font-family: inherit;
    font-size: 14px;
    color: var(--ink);
    background: var(--surface);
    outline: none;
    transition: border-color .15s, box-shadow .15s;
    appearance: none;
  }

  .input:focus, .select:focus, .textarea:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(29,111,219,.12);
  }

  .textarea { resize: vertical; min-height: 100px; font-family: 'DM Mono', monospace; font-size: 12px; }

  /* ── Buttons ── */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 10px 18px;
    border-radius: var(--r);
    font-family: inherit;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border: none;
    transition: all .15s;
    white-space: nowrap;
  }

  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { background: var(--accent-2); }
  .btn-primary:disabled { opacity: .5; cursor: not-allowed; }

  .btn-secondary { background: var(--surface-3); color: var(--ink-2); border: 1.5px solid var(--border); }
  .btn-secondary:hover { background: var(--border); }

  .btn-danger { background: var(--danger-bg); color: var(--danger); }
  .btn-danger:hover { background: #fca5a5; }

  .btn-ghost { background: transparent; color: var(--ink-3); }
  .btn-ghost:hover { background: var(--surface-3); color: var(--ink); }

  .btn-sm { padding: 6px 12px; font-size: 13px; }
  .btn-full { width: 100%; justify-content: center; }
  .btn-icon { padding: 8px; border-radius: 8px; }

  /* ── Cards ── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    box-shadow: var(--shadow-sm);
  }

  .card-header {
    padding: 20px 24px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .card-title { font-size: 15px; font-weight: 600; color: var(--ink); }
  .card-body { padding: 20px 24px; }

  /* ── Stats row ── */
  .stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 28px; }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--r-lg);
    padding: 20px 22px;
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .stat-icon {
    width: 44px; height: 44px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
  }

  .stat-value { font-size: 24px; font-weight: 600; line-height: 1; color: var(--ink); }
  .stat-label { font-size: 12px; color: var(--ink-3); margin-top: 3px; }

  /* ── Table ── */
  .table-wrap { overflow-x: auto; border-radius: var(--r-lg); border: 1px solid var(--border); }

  table { width: 100%; border-collapse: collapse; background: var(--surface); }
  thead { background: var(--surface-2); }
  th {
    padding: 11px 16px;
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: .4px;
    text-transform: uppercase;
    color: var(--ink-3);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  td {
    padding: 13px 16px;
    font-size: 14px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }

  tr:last-child td { border-bottom: none; }
  tr:hover td { background: var(--surface-2); }

  .mono { font-family: 'DM Mono', monospace; font-size: 12px; color: var(--ink-3); }

  /* ── Badges ── */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 9px;
    border-radius: 99px;
    font-size: 12px;
    font-weight: 500;
  }

  .badge-success { background: var(--success-bg); color: var(--success); }
  .badge-danger  { background: var(--danger-bg);  color: var(--danger);  }
  .badge-warn    { background: var(--warn-bg);     color: var(--warn);    }
  .badge-info    { background: var(--accent-bg);   color: var(--accent);  }
  .badge-neutral { background: var(--surface-3);   color: var(--ink-3);   }

  /* ── Alerts ── */
  .alert {
    padding: 13px 16px;
    border-radius: var(--r);
    font-size: 14px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 16px;
  }

  .alert-error   { background: var(--danger-bg);  color: var(--danger);  border: 1px solid #fca5a5; }
  .alert-success { background: var(--success-bg); color: var(--success); border: 1px solid #86efac; }
  .alert-warn    { background: var(--warn-bg);     color: var(--warn);    border: 1px solid #fcd34d; }
  .alert-info    { background: var(--accent-bg);   color: var(--accent);  border: 1px solid #93c5fd; }

  /* ── Modal ── */
  .modal-backdrop {
    position: fixed; inset: 0;
    background: rgba(15,25,35,.5);
    backdrop-filter: blur(3px);
    z-index: 200;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    animation: fadeIn .15s;
  }

  .modal {
    background: var(--surface);
    border-radius: var(--r-lg);
    box-shadow: var(--shadow-lg);
    width: 100%;
    max-width: 520px;
    max-height: 90vh;
    overflow-y: auto;
    animation: slideUp .18s;
  }

  .modal-header {
    padding: 22px 24px 16px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .modal-title { font-size: 16px; font-weight: 600; }
  .modal-body  { padding: 22px 24px; }
  .modal-footer { padding: 16px 24px; border-top: 1px solid var(--border); display: flex; gap: 10px; justify-content: flex-end; }

  @keyframes fadeIn  { from { opacity: 0; } to { opacity: 1; } }
  @keyframes slideUp { from { transform: translateY(16px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

  /* ── Key box ── */
  .key-box {
    background: var(--ink);
    color: #7ee787;
    font-family: 'DM Mono', monospace;
    font-size: 11px;
    line-height: 1.7;
    padding: 16px;
    border-radius: var(--r);
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    margin: 12px 0;
  }

  /* ── Upload zone ── */
  .drop-zone {
    border: 2px dashed var(--border);
    border-radius: var(--r-lg);
    padding: 40px 24px;
    text-align: center;
    cursor: pointer;
    transition: all .2s;
    background: var(--surface);
  }

  .drop-zone:hover, .drop-zone.over { border-color: var(--accent); background: var(--accent-bg); }
  .drop-zone-icon { font-size: 36px; margin-bottom: 12px; }
  .drop-zone p { font-size: 14px; color: var(--ink-3); }
  .drop-zone strong { color: var(--accent); }

  /* ── Empty state ── */
  .empty { text-align: center; padding: 60px 24px; color: var(--ink-3); }
  .empty-icon { font-size: 48px; margin-bottom: 16px; }
  .empty h3 { font-size: 16px; font-weight: 600; color: var(--ink-2); margin-bottom: 6px; }
  .empty p  { font-size: 14px; }

  /* ── Spinner ── */
  .spin {
    display: inline-block;
    width: 16px; height: 16px;
    border: 2px solid rgba(255,255,255,.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin .7s linear infinite;
  }
  .spin-dark { border-color: var(--border); border-top-color: var(--accent); }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Utils ── */
  .flex  { display: flex; }
  .gap-2 { gap: 8px; }
  .gap-3 { gap: 12px; }
  .mt-1  { margin-top: 4px; }
  .mt-2  { margin-top: 8px; }
  .mt-3  { margin-top: 12px; }
  .mt-4  { margin-top: 16px; }
  .mb-4  { margin-bottom: 16px; }
  .text-sm  { font-size: 13px; }
  .text-xs  { font-size: 12px; }
  .text-muted { color: var(--ink-3); }
  .truncate { overflow: hidden; white-space: nowrap; text-overflow: ellipsis; max-width: 200px; }
`;

// ─── Small components ─────────────────────────────────────────────────────────

function Alert({ type = "error", children, onClose }) {
  const icons = { error: "⚠️", success: "✓", warn: "⚠", info: "ℹ" };
  return (
    <div className={`alert alert-${type}`}>
      <span>{icons[type]}</span>
      <span style={{ flex: 1 }}>{children}</span>
      {onClose && <button onClick={onClose} className="btn btn-ghost btn-sm btn-icon" style={{ padding: "2px 6px" }}>×</button>}
    </div>
  );
}

function Spinner({ dark }) {
  return <span className={`spin${dark ? " spin-dark" : ""}`} />;
}

function Badge({ status }) {
  if (status === "ACTIVE")   return <span className="badge badge-success">● Active</span>;
  if (status === "EXPIRED")  return <span className="badge badge-warn">⏱ Expired</span>;
  if (status === "REVOKED")  return <span className="badge badge-danger">✕ Revoked</span>;
  return <span className="badge badge-neutral">{status}</span>;
}

function Modal({ title, onClose, footer, children }) {
  return (
    <div className="modal-backdrop" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal">
        <div className="modal-header">
          <span className="modal-title">{title}</span>
          <button className="btn btn-ghost btn-icon" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-footer">{footer}</div>}
      </div>
    </div>
  );
}

function CopyBtn({ text, label = "Copy" }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button className="btn btn-secondary btn-sm" onClick={copy}>
      {copied ? "✓ Copied" : label}
    </button>
  );
}

// ─── Auth pages ───────────────────────────────────────────────────────────────

function AuthPage({ onLogin }) {
  const [tab, setTab] = useState("login");
  const [form, setForm] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(null); // { token, message } after register
  const [verifyToken, setVerifyToken] = useState("");

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));

  async function handleRegister() {
    setError(""); setLoading(true);
    try {
      const res = await Auth.register({
        email: form.email, password: form.password,
        username: form.username, full_name: form.full_name || "",
        role: form.role || "PATIENT",
      });
      setPending({
        token: res.verification_token,
        expires: res.token_expires_at,
        message: `Account created! In production, a verification email is sent. For dev, the token is shown below.`,
      });
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  async function handleVerify() {
    setError(""); setLoading(true);
    try {
      const res = await Auth.verify(verifyToken);
      // Save private key in session so login doesn't need it
      const sess = Session.load() || {};
      sess.private_key_pem = res.private_key_pem;
      sess.public_key_hash = res.public_key_hash;
      sess.public_key_hex  = res.public_key_hex;
      Session.save(sess);
      setPending(null);
      setTab("login");
      setError(""); 
      // Show success
      setForm(f => ({ ...f, _verified: true }));
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  async function handleLogin() {
    setError(""); setLoading(true);
    try {
      const res = await Auth.login({ email: form.email, password: form.password });
      const existing = Session.load() || {};
      Session.save({ ...existing, token: res.access_token, email: res.email,
        user_id: res.user_id, username: res.username, role: res.role,
        public_key_hash: res.public_key_hash, public_key_compressed: res.public_key_compressed,
      });
      onLogin();
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  }

  // Verify step after register
  if (pending) return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="auth-logo">
          <h1>MedLedger</h1>
          <p>Email Verification</p>
        </div>
        <Alert type="info">{pending.message}</Alert>
        <div className="key-box">{pending.token}</div>
        <div className="flex gap-2 mb-4">
          <CopyBtn text={pending.token} label="Copy Token" />
        </div>
        {error && <Alert type="error">{error}</Alert>}
        <div className="field">
          <label>Paste Verification Token</label>
          <input className="input" value={verifyToken} onChange={e => setVerifyToken(e.target.value)} placeholder="Token from email..." />
        </div>
        <button className="btn btn-primary btn-full" onClick={handleVerify} disabled={loading || !verifyToken}>
          {loading ? <Spinner /> : "Verify & Activate Account"}
        </button>
        <div style={{ marginTop: 16, textAlign: "center" }}>
          <button className="btn btn-ghost btn-sm" onClick={() => setPending(null)}>← Back to login</button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="auth-logo">
          <h1>MedLedger</h1>
          <p>Patient-controlled healthcare vault</p>
        </div>
        <div className="auth-tabs">
          <button className={`auth-tab${tab === "login" ? " active" : ""}`} onClick={() => { setTab("login"); setError(""); }}>Sign In</button>
          <button className={`auth-tab${tab === "register" ? " active" : ""}`} onClick={() => { setTab("register"); setError(""); }}>Register</button>
        </div>
        {form._verified && <Alert type="success">Email verified! You can now sign in.</Alert>}
        {error && <Alert type="error">{error}</Alert>}

        {tab === "login" ? (
          <>
            <div className="field"><label>Email</label><input className="input" type="email" value={form.email || ""} onChange={set("email")} placeholder="you@example.com" /></div>
            <div className="field"><label>Password</label><input className="input" type="password" value={form.password || ""} onChange={set("password")} placeholder="••••••••" /></div>
            <button className="btn btn-primary btn-full" onClick={handleLogin} disabled={loading}>
              {loading ? <Spinner /> : "Sign In"}
            </button>
          </>
        ) : (
          <>
            <div className="field"><label>Email</label><input className="input" type="email" value={form.email || ""} onChange={set("email")} placeholder="you@example.com" /></div>
            <div className="field"><label>Username</label><input className="input" value={form.username || ""} onChange={set("username")} placeholder="alice" /></div>
            <div className="field"><label>Full Name <span className="text-muted text-xs">(optional)</span></label><input className="input" value={form.full_name || ""} onChange={set("full_name")} /></div>
            <div className="field"><label>Password</label><input className="input" type="password" value={form.password || ""} onChange={set("password")} placeholder="Min 8 characters" /></div>
            <div className="field">
              <label>Role</label>
              <select className="select" value={form.role || "PATIENT"} onChange={set("role")}>
                <option value="PATIENT">Patient</option>
                <option value="DOCTOR">Doctor</option>
              </select>
            </div>
            <button className="btn btn-primary btn-full" onClick={handleRegister} disabled={loading}>
              {loading ? <Spinner /> : "Create Account"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

function Dashboard({ session }) {
  const [records, setRecords] = useState([]);
  const [grants, setGrants] = useState([]);
  const [inbox, setInbox] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const [recs, grs, inb] = await Promise.all([
          Vault.records(session.token),
          session.private_key_pem ? Vault.permissions({ private_key_pem: session.private_key_pem }, session.token) : Promise.resolve([]),
          session.private_key_pem ? Vault.inbox({ private_key_pem: session.private_key_pem }, session.token) : Promise.resolve([]),
        ]);
        setRecords(recs); setGrants(grs); setInbox(inb);
      } catch {}
      setLoading(false);
    }
    load();
  }, []);

  const activeGrants = grants.filter(g => !g.revoked && g.time_valid).length;
  const inboxActive  = inbox.filter(g => !g.revoked && g.time_valid).length;
  const totalSize    = records.reduce((s, r) => s + r.size_bytes, 0);

  const fmtBytes = (b) => b > 1048576 ? `${(b/1048576).toFixed(1)} MB` : b > 1024 ? `${(b/1024).toFixed(0)} KB` : `${b} B`;

  return (
    <div className="content">
      <div className="stats-row">
        {[
          { icon: "🗂️", color: "#eef4ff", value: records.length, label: "Medical Records" },
          { icon: "📤", color: "#dcfce7", value: activeGrants,   label: "Active Grants" },
          { icon: "📥", color: "#fef3c7", value: inboxActive,    label: "Inbox Access" },
          { icon: "💾", color: "#f1f4f8", value: fmtBytes(totalSize), label: "Total Stored" },
        ].map(({ icon, color, value, label }) => (
          <div key={label} className="stat-card">
            <div className="stat-icon" style={{ background: color }}>{icon}</div>
            <div>
              <div className="stat-value">{loading ? "–" : value}</div>
              <div className="stat-label">{label}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent Records</span>
        </div>
        {loading ? (
          <div className="card-body" style={{ textAlign: "center", padding: 40 }}><Spinner dark /></div>
        ) : records.length === 0 ? (
          <div className="empty"><div className="empty-icon">📂</div><h3>No records yet</h3><p>Upload your first medical record from the Vault tab.</p></div>
        ) : (
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead><tr><th>File</th><th>Size</th><th>Tags</th><th>Uploaded</th></tr></thead>
              <tbody>
                {records.slice(0, 5).map(r => (
                  <tr key={r.record_id}>
                    <td><div style={{ fontWeight: 500 }}>{r.filename}</div><div className="mono">{r.record_id.slice(0, 8)}…</div></td>
                    <td className="text-muted text-sm">{fmtBytes(r.size_bytes)}</td>
                    <td>{r.tags?.map(t => <span key={t} className="badge badge-info" style={{ marginRight: 4 }}>{t}</span>)}</td>
                    <td className="text-muted text-sm">{r.created_at?.slice(0, 16).replace("T", " ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Vault / Records ──────────────────────────────────────────────────────────

function VaultPage({ session }) {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [uploadModal, setUploadModal] = useState(false);
  const [downloadModal, setDownloadModal] = useState(null);
  const [grantModal, setGrantModal] = useState(null);
  const [error, setError] = useState("");
  const fileRef = useRef();

  const load = useCallback(async () => {
    setLoading(true);
    try { setRecords(await Vault.records(session.token)); }
    catch (e) { setError(e.message); }
    setLoading(false);
  }, [session.token]);

  useEffect(() => { load(); }, [load]);

  const fmtBytes = (b) => b > 1048576 ? `${(b/1048576).toFixed(1)} MB` : b > 1024 ? `${(b/1024).toFixed(0)} KB` : `${b} B`;

  return (
    <div className="content">
      {error && <Alert type="error" onClose={() => setError("")}>{error}</Alert>}
      {!session.private_key_pem && (
        <Alert type="warn">Your private key is not in this session. Upload and download operations require it. It was shown once after email verification.</Alert>
      )}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Medical Records Vault</span>
          <button className="btn btn-primary btn-sm" onClick={() => setUploadModal(true)} disabled={!session.private_key_pem}>
            ↑ Upload Record
          </button>
        </div>
        {loading ? (
          <div className="card-body" style={{ textAlign: "center", padding: 48 }}><Spinner dark /></div>
        ) : records.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">🔐</div>
            <h3>Vault is empty</h3>
            <p>Upload a medical record to get started.</p>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead><tr><th>Filename</th><th>Record ID</th><th>Size</th><th>Type</th><th>Tags</th><th>Date</th><th>Actions</th></tr></thead>
              <tbody>
                {records.map(r => (
                  <tr key={r.record_id}>
                    <td><span style={{ fontWeight: 500 }}>📄 {r.filename}</span></td>
                    <td><span className="mono">{r.record_id.slice(0, 8)}…</span></td>
                    <td className="text-sm text-muted">{fmtBytes(r.size_bytes)}</td>
                    <td className="text-sm text-muted">{r.mime_type?.split("/")[1] || r.mime_type}</td>
                    <td>{r.tags?.map(t => <span key={t} className="badge badge-neutral" style={{ marginRight: 4 }}>{t}</span>)}</td>
                    <td className="text-sm text-muted">{r.created_at?.slice(0, 10)}</td>
                    <td>
                      <div className="flex gap-2">
                        <button className="btn btn-secondary btn-sm" onClick={() => setDownloadModal(r)} disabled={!session.private_key_pem}>↓</button>
                        <button className="btn btn-secondary btn-sm" onClick={() => setGrantModal(r)} disabled={!session.private_key_pem}>Share</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {uploadModal && <UploadModal session={session} onClose={() => { setUploadModal(false); load(); }} />}
      {downloadModal && <DownloadModal record={downloadModal} session={session} onClose={() => setDownloadModal(null)} />}
      {grantModal && <GrantModal record={grantModal} session={session} onClose={() => setGrantModal(null)} />}
    </div>
  );
}

function UploadModal({ session, onClose }) {
  const [file, setFile] = useState(null);
  const [tags, setTags] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef();

  const handleFile = (f) => setFile(f);

  async function upload() {
    if (!file) return;
    setLoading(true); setError("");
    try {
      const buf = await file.arrayBuffer();
      const hex = toHex(buf);
      const res = await Vault.upload({
        private_key_pem: session.private_key_pem,
        filename: file.name,
        plaintext_hex: hex,
        tags: tags ? tags.split(",").map(t => t.trim()).filter(Boolean) : [],
      }, session.token);
      setSuccess(res);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  if (success) return (
    <Modal title="Upload Successful" onClose={onClose}
      footer={<button className="btn btn-primary" onClick={onClose}>Done</button>}>
      <Alert type="success">File encrypted and stored securely.</Alert>
      <div className="field"><label>Record ID</label><div className="mono" style={{ padding: "8px 0" }}>{success.record_id}</div></div>
      <div className="flex gap-2">
        <CopyBtn text={success.record_id} label="Copy Record ID" />
      </div>
    </Modal>
  );

  return (
    <Modal title="Upload Medical Record" onClose={onClose}
      footer={<>
        <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={upload} disabled={!file || loading}>
          {loading ? <><Spinner /> Encrypting…</> : "Upload & Encrypt"}
        </button>
      </>}>
      {error && <Alert type="error">{error}</Alert>}
      <div
        className={`drop-zone${dragging ? " over" : ""}`}
        onClick={() => inputRef.current.click()}
        onDragOver={e => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}>
        <input ref={inputRef} type="file" style={{ display: "none" }} onChange={e => handleFile(e.target.files[0])} />
        <div className="drop-zone-icon">{file ? "📄" : "☁️"}</div>
        {file ? <p><strong>{file.name}</strong> ({(file.size/1024).toFixed(1)} KB)</p>
               : <p><strong>Click to browse</strong> or drag & drop a file</p>}
      </div>
      <div className="field mt-3">
        <label>Tags <span className="text-muted text-xs">(comma-separated, optional)</span></label>
        <input className="input" value={tags} onChange={e => setTags(e.target.value)} placeholder="lab-result, 2024, cardiology" />
      </div>
    </Modal>
  );
}

function DownloadModal({ record, session, onClose }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function download() {
    setLoading(true); setError("");
    try {
      const res = await Vault.download(record.record_id, { private_key_pem: session.private_key_pem }, session.token);
      const bytes = fromHex(res.plaintext_hex);
      const blob = new Blob([bytes], { type: res.mime_type || "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = res.filename; a.click();
      URL.revokeObjectURL(url);
      onClose();
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  return (
    <Modal title="Download & Decrypt" onClose={onClose}
      footer={<>
        <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={download} disabled={loading}>
          {loading ? <><Spinner /> Decrypting…</> : "↓ Download Decrypted"}
        </button>
      </>}>
      {error && <Alert type="error">{error}</Alert>}
      <p className="text-sm text-muted">The file will be decrypted in your browser using your private key and downloaded.</p>
      <div className="mt-3" style={{ background: "var(--surface-3)", borderRadius: "var(--r)", padding: "14px 16px" }}>
        <div><strong>{record.filename}</strong></div>
        <div className="mono mt-1">{record.record_id}</div>
      </div>
    </Modal>
  );
}

function GrantModal({ record, session, onClose }) {
  const [granteeKey, setGranteeKey] = useState("");
  const [level, setLevel] = useState("view_only");
  const [hours, setHours] = useState(24);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(null);

  async function grant() {
    setLoading(true); setError("");
    try {
      const res = await Vault.grant({
        private_key_pem: session.private_key_pem,
        record_id: record.record_id,
        grantee_public_key_hex: granteeKey.trim(),
        permission_level: level,
        duration_hours: parseFloat(hours),
      }, session.token);
      setSuccess(res);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }

  if (success) return (
    <Modal title="Access Granted" onClose={onClose} footer={<button className="btn btn-primary" onClick={onClose}>Done</button>}>
      <Alert type="success">Access granted successfully.</Alert>
      <div className="field"><label>Grant ID</label><div className="mono" style={{ padding: "8px 0", wordBreak: "break-all" }}>{success.grant_id}</div></div>
      <div className="field"><label>Expires</label><div className="text-sm text-muted">{success.time_end?.slice(0, 19).replace("T", " ")} UTC</div></div>
    </Modal>
  );

  return (
    <Modal title={`Share Access — ${record.filename}`} onClose={onClose}
      footer={<>
        <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
        <button className="btn btn-primary" onClick={grant} disabled={loading || !granteeKey}>
          {loading ? <Spinner /> : "Grant Access"}
        </button>
      </>}>
      {error && <Alert type="error">{error}</Alert>}
      <div className="field">
        <label>Grantee Public Key (hex)</label>
        <textarea className="textarea" value={granteeKey} onChange={e => setGranteeKey(e.target.value)} placeholder="04abc123…  (the recipient's public_key_hex)" />
      </div>
      <div className="field">
        <label>Permission Level</label>
        <select className="select" value={level} onChange={e => setLevel(e.target.value)}>
          <option value="view_only">View Only</option>
          <option value="view_download">View + Download</option>
        </select>
      </div>
      <div className="field">
        <label>Duration (hours)</label>
        <input className="input" type="number" min="1" max="8760" value={hours} onChange={e => setHours(e.target.value)} />
      </div>
    </Modal>
  );
}

// ─── Permissions / Grants ─────────────────────────────────────────────────────

function PermissionsPage({ session }) {
  const [tab, setTab] = useState("outbox");
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!session.private_key_pem) { setLoading(false); return; }
    setLoading(true);
    try {
      const data = tab === "outbox"
        ? await Vault.permissions({ private_key_pem: session.private_key_pem }, session.token)
        : await Vault.inbox({ private_key_pem: session.private_key_pem }, session.token);
      setItems(data);
    } catch (e) { setError(e.message); }
    setLoading(false);
  }, [tab, session]);

  useEffect(() => { load(); }, [load]);

  async function handleRevoke(grant_id) {
    setRevoking(grant_id);
    try {
      await Vault.revoke({ private_key_pem: session.private_key_pem, grant_id }, session.token);
      load();
    } catch (e) { setError(e.message); }
    setRevoking(null);
  }

  const grantStatus = (g) => g.revoked ? "REVOKED" : g.time_valid ? "ACTIVE" : "EXPIRED";

  return (
    <div className="content">
      {error && <Alert type="error" onClose={() => setError("")}>{error}</Alert>}
      {!session.private_key_pem && (
        <Alert type="warn">Private key not in session — permission listing requires it.</Alert>
      )}
      <div className="flex gap-2 mb-4">
        {["outbox", "inbox"].map(t => (
          <button key={t} className={`btn ${tab === t ? "btn-primary" : "btn-secondary"}`} onClick={() => setTab(t)}>
            {t === "outbox" ? "📤 Granted by Me" : "📥 Granted to Me"}
          </button>
        ))}
      </div>
      <div className="card">
        <div className="card-header">
          <span className="card-title">{tab === "outbox" ? "Access Grants Issued" : "Access Grants Received"}</span>
        </div>
        {loading ? (
          <div className="card-body" style={{ textAlign: "center", padding: 48 }}><Spinner dark /></div>
        ) : items.length === 0 ? (
          <div className="empty">
            <div className="empty-icon">{tab === "outbox" ? "📤" : "📥"}</div>
            <h3>No grants {tab === "outbox" ? "issued" : "received"}</h3>
            <p>{tab === "outbox" ? "Share a record from the Vault page." : "No one has shared records with you yet."}</p>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: "none", borderRadius: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>File</th>
                  <th>Grant ID</th>
                  <th>{tab === "outbox" ? "Grantee" : "Grantor"}</th>
                  <th>Level</th>
                  <th>Expires</th>
                  <th>Status</th>
                  <th>Sig</th>
                  {tab === "outbox" && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {items.map(g => (
                  <tr key={g.grant_id}>
                    <td style={{ fontWeight: 500 }}>📄 {g.filename}</td>
                    <td><span className="mono">{g.grant_id.slice(0, 8)}…</span></td>
                    <td><span className="mono">{(tab === "outbox" ? g.grantee_key_hash : g.grantor_key_hash).slice(0, 12)}…</span></td>
                    <td><span className={`badge ${g.permission_level === "view_download" ? "badge-info" : "badge-neutral"}`}>{g.permission_level}</span></td>
                    <td className="text-sm text-muted">{g.time_end?.slice(0, 16).replace("T", " ")}</td>
                    <td><Badge status={grantStatus(g)} /></td>
                    <td>{g.signature_valid ? <span className="badge badge-success">✓</span> : <span className="badge badge-danger">✗</span>}</td>
                    {tab === "outbox" && (
                      <td>
                        {!g.revoked && (
                          <button className="btn btn-danger btn-sm" onClick={() => handleRevoke(g.grant_id)} disabled={revoking === g.grant_id}>
                            {revoking === g.grant_id ? <Spinner /> : "Revoke"}
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Settings / Key Management ────────────────────────────────────────────────

function SettingsPage({ session, onLogout }) {
  const [rotating, setRotating] = useState(false);
  const [rotateResult, setRotateResult] = useState(null);
  const [error, setError] = useState("");
  const [confirmRotate, setConfirmRotate] = useState(false);

  // For rotate-key we need to generate a new keypair client-side.
  // We do this by calling the API — in a real SSI setup the client generates it locally.
  // For this demo, we call /api/auth/register flow or prompt user to paste a new key.
  // Simplest: generate via a small Web Crypto helper.

  async function generateNewKey() {
    // Generate P-256 keypair in browser via Web Crypto
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const rawPub = await crypto.subtle.exportKey("raw", kp.publicKey);
    const pkcs8  = await crypto.subtle.exportKey("pkcs8", kp.privateKey);

    const pubHex = toHex(rawPub);

    // Encode pkcs8 as PEM
    const b64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
    const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g).join("\n")}\n-----END PRIVATE KEY-----\n`;

    return { pem, pubHex };
  }

  async function handleRotate() {
    if (!session.private_key_pem) return;
    setRotating(true); setError("");
    try {
      const { pem: newPem, pubHex: newPub } = await generateNewKey();
      const res = await Vault.rotateKey({
        old_private_key_pem: session.private_key_pem,
        new_private_key_pem: newPem,
        new_public_key_hex: newPub,
      }, session.token);
      // Update session with new key
      const s = Session.load();
      s.private_key_pem = newPem;
      s.public_key_hex  = newPub;
      Session.save(s);
      setRotateResult({ ...res, newPem, newPub });
    } catch (e) { setError(e.message); }
    setRotating(false); setConfirmRotate(false);
  }

  const s = session;

  return (
    <div className="content">
      {error && <Alert type="error" onClose={() => setError("")}>{error}</Alert>}

      <div className="card mb-4" style={{ marginBottom: 20 }}>
        <div className="card-header"><span className="card-title">Account</span></div>
        <div className="card-body">
          <table style={{ width: "auto", border: "none", background: "none" }}>
            <tbody>
              {[
                ["Email", s.email],
                ["Username", s.username],
                ["Role", s.role],
                ["User ID", s.user_id],
                ["Public Key Hash", s.public_key_hash ? s.public_key_hash.slice(0, 24) + "…" : "—"],
              ].map(([k, v]) => (
                <tr key={k} style={{ borderBottom: "none" }}>
                  <td style={{ padding: "6px 16px 6px 0", color: "var(--ink-3)", fontSize: 13, fontWeight: 500, borderBottom: "none" }}>{k}</td>
                  <td style={{ padding: "6px 0", fontSize: 14, borderBottom: "none" }}>{v || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card mb-4" style={{ marginBottom: 20 }}>
        <div className="card-header"><span className="card-title">Private Key</span></div>
        <div className="card-body">
          {s.private_key_pem ? (
            <>
              <Alert type="warn">Your private key is stored in sessionStorage only — it is never sent to the server. It will be cleared when you close this tab.</Alert>
              <div className="key-box">{s.private_key_pem}</div>
              <div className="flex gap-2">
                <CopyBtn text={s.private_key_pem} label="Copy Private Key" />
                <button className="btn btn-secondary btn-sm" onClick={() => {
                  const blob = new Blob([s.private_key_pem], { type: "text/plain" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a"); a.href = url; a.download = "medledger_private_key.pem"; a.click();
                  URL.revokeObjectURL(url);
                }}>↓ Download PEM</button>
              </div>
            </>
          ) : (
            <Alert type="warn">No private key in this session. Paste it below to enable vault operations.</Alert>
          )}
          <div className="field mt-3">
            <label>Paste / Update Private Key</label>
            <textarea className="textarea" placeholder="-----BEGIN EC PRIVATE KEY-----&#10;…&#10;-----END EC PRIVATE KEY-----"
              onBlur={e => {
                if (!e.target.value.trim()) return;
                const s2 = Session.load() || {};
                s2.private_key_pem = e.target.value.trim();
                Session.save(s2);
                window.location.reload();
              }} />
          </div>
        </div>
      </div>

      <div className="card mb-4" style={{ marginBottom: 20 }}>
        <div className="card-header"><span className="card-title">Key Rotation</span></div>
        <div className="card-body">
          {rotateResult ? (
            <>
              <Alert type="success">Key rotated. {rotateResult.rotated_records} records re-encrypted. {rotateResult.revoked_grants} grants revoked.</Alert>
              <div className="key-box">{rotateResult.newPem}</div>
              <div className="flex gap-2">
                <CopyBtn text={rotateResult.newPem} label="Copy New Key" />
              </div>
            </>
          ) : (
            <>
              <p className="text-sm text-muted" style={{ marginBottom: 14 }}>
                Generates a new P-256 keypair in your browser, re-encrypts all your record DEKs under the new key, and revokes all existing grants. This cannot be undone.
              </p>
              {!confirmRotate ? (
                <button className="btn btn-danger" onClick={() => setConfirmRotate(true)} disabled={!s.private_key_pem}>
                  🔑 Rotate Key
                </button>
              ) : (
                <div>
                  <Alert type="warn">All grants will be revoked. Grantees must re-request access.</Alert>
                  <div className="flex gap-2 mt-2">
                    <button className="btn btn-secondary" onClick={() => setConfirmRotate(false)}>Cancel</button>
                    <button className="btn btn-danger" onClick={handleRotate} disabled={rotating}>
                      {rotating ? <><Spinner /> Rotating…</> : "Confirm Rotation"}
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header"><span className="card-title">Session</span></div>
        <div className="card-body">
          <p className="text-sm text-muted" style={{ marginBottom: 14 }}>Clears your JWT and private key from sessionStorage.</p>
          <button className="btn btn-danger" onClick={onLogout}>Sign Out</button>
        </div>
      </div>
    </div>
  );
}

// ─── Shell ────────────────────────────────────────────────────────────────────

const PAGES = [
  { id: "dashboard",   label: "Dashboard",     icon: "⊞",  section: "main" },
  { id: "vault",       label: "Vault",         icon: "🔐", section: "main" },
  { id: "permissions", label: "Permissions",   icon: "📋", section: "main" },
  { id: "settings",    label: "Settings & Keys", icon: "⚙", section: "account" },
];

function Shell() {
  const [session, setSession] = useState(null);
  const [page, setPage] = useState("dashboard");

  useEffect(() => {
    const s = Session.load();
    if (s?.token) setSession(s);
  }, []);

  function handleLogin() {
    const s = Session.load();
    if (s?.token) setSession(s);
  }

  function handleLogout() {
    Session.clear();
    setSession(null);
    setPage("dashboard");
  }

  if (!session) return <AuthPage onLogin={handleLogin} />;

  const titles = {
    dashboard:   { title: "Dashboard",      sub: "Overview of your medical data" },
    vault:       { title: "Vault",          sub: "Encrypted medical records" },
    permissions: { title: "Permissions",    sub: "Access grants issued and received" },
    settings:    { title: "Settings",       sub: "Account, keys, and security" },
  };

  const { title, sub } = titles[page] || titles.dashboard;

  const sections = ["main", "account"];

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <h1>MedLedger</h1>
          <span>Healthcare Vault</span>
        </div>
        <nav className="sidebar-nav">
          {sections.map(sec => {
            const items = PAGES.filter(p => p.section === sec);
            return (
              <div key={sec} className="nav-section">
                <div className="nav-label">{sec}</div>
                {items.map(p => (
                  <button key={p.id} className={`nav-item${page === p.id ? " active" : ""}`} onClick={() => setPage(p.id)}>
                    <span className="icon">{p.icon}</span>
                    {p.label}
                  </button>
                ))}
              </div>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="user-chip">
            <div className="user-avatar">{(session.username || session.email || "U")[0].toUpperCase()}</div>
            <div className="user-info">
              <div className="user-name">{session.username || session.email}</div>
              <div className="user-role">{session.role || "PATIENT"}</div>
            </div>
          </div>
        </div>
      </aside>

      <div className="main">
        <div className="topbar">
          <div>
            <div className="page-title">{title}</div>
            <div className="page-subtitle">{sub}</div>
          </div>
          <div className="flex gap-2">
            <span className="badge badge-success" style={{ fontSize: 12 }}>● API Connected</span>
          </div>
        </div>

        {page === "dashboard"   && <Dashboard   session={session} />}
        {page === "vault"       && <VaultPage   session={session} />}
        {page === "permissions" && <PermissionsPage session={session} />}
        {page === "settings"    && <SettingsPage session={session} onLogout={handleLogout} />}
      </div>
    </div>
  );
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────

const styleEl = document.createElement("style");
styleEl.textContent = css;
document.head.appendChild(styleEl);

createRoot(document.getElementById("root")).render(<Shell />);
