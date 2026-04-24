# Upload Bug Report — MedLedger App

## Summary

Two distinct bugs, both in `medledger_app.py → _do_upload`. The app sends the
wrong key material to the server, causing a silent mismatch that produces no
visible record. The crash immediately after is a direct consequence of that
mismatch landing in `_on_upload_done`.

---

## Bug 1 — Wrong key sent: private key used where upload already derives public internally

### What the code does

```python
# medledger_app.py  _do_upload()
def _work():
    return _post(self.base_url, "/api/vault/upload", {
        "private_key_pem": pem,       # ← sends private key
        "filename":        p.name,
        "plaintext_hex":   raw.hex(),
        "tags":            tags,
    }, self.token)
```

This is actually **correct for the upload endpoint** — `UploadRequest` expects
`private_key_pem` and the server-side `transceiver.upload()` calls
`_caller_keys(private_key_pem)` to derive the public key internally:

```python
# transceiver.py  upload()
pub_hex, pub_hash = self._caller_keys(caller_private_key_pem)
dek_bundle = ecies_encrypt(pub_hex, dek)   # encrypts DEK under owner's public key
rec = VaultRecord(owner_key_hash=pub_hash, ...)
```

So the upload itself **encrypts and stores correctly**. The record IS written to
the DB. However …

---

## Bug 2 (root cause of "no record to download") — `list_records` queries by the wrong `public_key_hash`

### The mismatch

After upload, when the app loads the records list:

```python
# vault.py  list_records endpoint
records = store.list_records_by_owner(caller.public_key_hash)
```

`caller.public_key_hash` comes from **the JWT / database** via `require_auth`:

```python
# deps.py  require_auth
return CallerIdentity(
    ...
    public_key_hash=user.public_key_hash or "",   # ← from DB
)
```

The record was stored with `owner_key_hash` derived by
`_caller_keys(private_key_pem)` at upload time — i.e. computed fresh from the
PEM on every call via `key_manager.get_public_key_from_private()`.

These two hashes **should be identical** — the same private key always produces
the same public key. But they diverge if:

1. **The user loaded a different `.pem` file than the one registered** — e.g.
   they browsed to an old key or a wrong file in the new `_prompt_for_key`
   dialog. The upload succeeds but stores `owner_key_hash = hash(wrong_key)`,
   which never matches `user.public_key_hash` in the DB.

2. **The key was rotated** — after `rotate_key`, the DB `public_key_hash` is
   updated but the old `.pem` in `.env/` or the session path is stale. Upload
   uses the old key, stores records under the old hash, `list_records` queries
   the new hash → no results.

3. **A subtle but real case introduced by this patch** — `_load_overview` does
   a **silent** `load_key()` (intentionally no dialog). If the key file is not
   found at that moment, overview loads without grants/inbox. But then when the
   user clicks Upload and `_ensure_key()` prompts them, they might pick a
   **different file** than the one whose hash is in the DB. Upload uses that
   file; list uses the DB hash. Mismatch.

### How to verify

Run this in psql after an upload that shows no record:

```sql
SELECT record_id, owner_key_hash FROM vault_records ORDER BY created_at DESC LIMIT 5;
SELECT public_key_hash FROM users WHERE username = '<your_username>';
```

If the two hashes differ, this is the bug.

---

## Bug 3 (crash after upload) — `_on_upload_done` crashes on unexpected result shape

### What happens

When the API returns a non-200 (e.g. 400 because the key hash didn't match any
registered user, or a server-side `VaultError`), `_post()` returns
`(None, "HTTP 400: …")`. But `_on_upload_done` does:

```python
def _on_upload_done(self, result, err):
    self._upload_btn.setEnabled(True)
    self._upload_btn.setText("🔒  Encrypt & Upload")
    if err:                            # err comes from ApiWorker exception only
        ...
        return
    resp, api_err = result             # ← CRASHES if result is (None, "HTTP 400:…")
                                       #   because resp = None, api_err = "HTTP 400:…"
                                       #   and then resp['filename'] on line below raises
```

Actually the unpack itself works (result is a tuple), but then:

```python
    self._upload_status.setText(
        f"✓  Uploaded '{resp['filename']}' …")   # ← TypeError: 'NoneType' object is not subscriptable
```

`resp` is `None` when the server returns an error, so `resp['filename']` raises
`TypeError`. Because this is in a signal handler connected to a `QThread`,
PyQt6 catches the exception, **tears down the signal connection**, and depending
on the PyQt6 version and platform this can cause the app to exit silently or
print a traceback and close the upload widget.

The `api_err` check exists but comes **after** the successful path is assumed:

```python
    resp, api_err = result
    if api_err:          # this branch is never reached when resp is None
        ...              # because the line above didn't crash yet — but
        return           # resp['filename'] crashes before this check matters
```

Wait — actually unpacking works fine, `resp=None`, `api_err="HTTP 400:…"`,
and `if api_err:` should catch it. **The real crash** is that `ApiWorker.done`
emits `(result, None)` where `result` is already the tuple `(None, "HTTP 400")`.
So in `_on_upload_done`, `err` is `None` (no exception), and
`result = (None, "HTTP 400:…")`. Unpacking: `resp=None`, `api_err="HTTP 400:…"`.
The `if api_err:` check fires correctly … **but** the status label
`setText` call tries to update a widget that may have been garbage-collected if
the upload scroll widget was re-created (switching away and back to the Upload
tab while uploading). That causes a `RuntimeError: wrapped C++ object deleted`
which crashes the signal handler and can close the app.

---

## Fixes Required

### Fix 1 — Ensure the key used for upload matches the DB hash

In `_do_upload`, after getting `pem`, derive the public key hash from it and
compare against `self.profile.get("public_key_hash")`. If they differ, warn
the user before sending:

```python
# In _do_upload, after pem = self._ensure_key()
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
import hashlib
try:
    priv    = load_pem_private_key(pem.encode(), password=None)
    pub_raw = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    derived_hash = hashlib.sha256(pub_raw).hexdigest()
    db_hash = self.profile.get("public_key_hash", "")
    if db_hash and derived_hash != db_hash:
        QMessageBox.warning(self, "Wrong Key File",
            "The selected private key does not match your registered public key.\n\n"
            "Please select the correct .pem file for this account.")
        return
except Exception as e:
    QMessageBox.critical(self, "Key Error", f"Could not read private key: {e}")
    return
```

### Fix 2 — Guard `resp` before accessing fields in `_on_upload_done`

```python
def _on_upload_done(self, result, err):
    self._upload_btn.setEnabled(True)
    self._upload_btn.setText("🔒  Encrypt & Upload")
    if err:
        self._upload_status.setText(f"✕ {err}")
        self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['red']};")
        return
    resp, api_err = result
    if api_err or resp is None:          # ← add `or resp is None`
        self._upload_status.setText(f"✕ {api_err or 'No response from server'}")
        self._upload_status.setStyleSheet(f"font-size: 12px; color: {C['red']};")
        return
    # safe to access resp fields below this line
    ...
```

### Fix 3 — Keep a strong reference to upload workers

`self._workers.append(w)` exists but the list is shared across all workers and
never pruned. If a finished worker is garbage-collected while its signal is
still pending delivery (rare but possible with rapid navigation), the handler
fires against a dead widget. Replace the append with a dedicated upload worker
reference:

```python
self._upload_worker = w   # strong reference scoped to upload only
self._workers.append(w)   # keep existing list too
```

---

## Files to Change

| File | Change |
|------|--------|
| `medledger_app.py` | Fix 1: key hash check in `_do_upload` |
| `medledger_app.py` | Fix 2: `or resp is None` guard in `_on_upload_done` |
| `medledger_app.py` | Fix 3: dedicated `self._upload_worker` reference |

No backend changes needed — the server-side logic is correct.
