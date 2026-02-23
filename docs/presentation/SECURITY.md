# Security Design — MedLedger

This document explains the security properties MedLedger provides, what assumptions it makes, and where the boundaries are. We've tried to be precise rather than promotional.

---

## Core Security Property

**A hospital administrator with full database access cannot read a patient's medical record without the patient's cryptographic signature.**

This is the central guarantee. Everything else follows from it.

---

## Cryptographic Primitives

### ECDSA P-256 (secp256r1)
Used for keypair generation and access permission signatures. P-256 is NIST-approved, widely audited, and used in TLS 1.3. Key generation happens client-side. The private key is never transmitted to or stored on the server — not encrypted, not hashed, not at all. Only the public key (and its SHA-256 hash as an identifier) lives on the server.

### AES-256-GCM
Used for encrypting medical records before they reach S3 storage. GCM mode provides authenticated encryption — it detects tampering as well as preventing decryption. Each record gets a unique IV. The encryption key is derived from the patient's private key, so a database breach without the private key yields undecryptable ciphertext.

### Shamir Secret Sharing (GF-256, 3-of-5)
Used for private key recovery. The patient's private key is split into 5 shares using Lagrange interpolation over GF(256). Any 3 shares are sufficient to reconstruct the key; fewer than 3 reveal nothing about the original. Shares are distributed to trusted parties chosen by the patient. This is information-theoretically secure — it holds even against unlimited computation.

---

## Access Permission Model

A permission grant is a signed JSON payload containing:

```json
{
  "patient_id": "...",
  "grantee_public_key_hash": "...",
  "record_id": "...",
  "valid_from": "2025-02-19T14:00:00Z",
  "valid_until": "2025-02-19T16:00:00Z",
  "permission_level": "view_only"
}
```

The server verifies the ECDSA signature on every access request — not once at grant time, but on every call. Time-window enforcement is done at the cryptographic layer, not the application layer. A revoked permission sets `is_revoked = true`; the next signature verification fails immediately.

The grantee is identified by `public_key_hash`, not a mutable username. Renaming a user account does not carry over access.

---

## Audit Trail

Every access attempt — successful or denied — is written to an append-only log. Log entries include:

- User ID of the requester
- Record ID targeted
- Action type (`RECORD_ACCESSED`, `PERMISSION_GRANTED`, `PERMISSION_REVOKED`, `LOGIN_FAILED`, etc.)
- Timestamp

The blockchain layer chains these entries by hash, so retroactive modification of any entry breaks the chain and is detectable. Admins cannot delete entries; the schema has no delete pathway for audit records.

---

## What We Don't Claim

**We are a hackathon project.** The following would be required before any production deployment:

- **Independent cryptographic audit.** The Shamir implementation uses a from-scratch GF-256 construction. It should be reviewed by a cryptographer before use in production. Standard libraries (e.g., `secrets` module, `python-shamir-mnemonic`) would be safer defaults.
- **Key management infrastructure.** Currently the private key is managed client-side with no hardware enclave or HSM backing. Production would need secure enclave support (e.g., iOS Secure Enclave, Android Keystore, TPM).
- **Blockchain consensus.** The current audit chain is a single-node hash chain. A real deployment would need a distributed consensus mechanism to make the log tamper-evident against the node operator as well.
- **HIPAA / regulatory compliance review.** The architecture is designed with HIPAA in mind, but a formal compliance assessment has not been performed.
- **Penetration testing.** The API has not been tested against adversarial inputs beyond the development team.

---

## Threat Model Summary

| Attacker | Capability | MedLedger's Defence |
|---|---|---|
| Malicious insider (admin) | Full DB read access | Records encrypted; no key stored server-side |
| Malicious insider (admin) | Audit log tampering | Hash-chained append-only log |
| Compromised doctor account | Valid credentials | Access still requires patient signature for each record |
| Database breach | Full table dump | Ciphertext only; keys not present |
| Man-in-the-middle | Network interception | ECDSA signatures verified server-side; CORS locked to known origins |
| Patient loses private key | Key unavailable | Shamir 3-of-5 recovery with chosen trustees |
| Stolen patient device | Private key exposure | Shamir recovery allows key rotation; old permissions can be revoked |

---

## Responsible Disclosure

This is a student hackathon project and is not deployed in any clinical environment. If you find a vulnerability in the design or implementation, please open an issue or contact the team directly. We welcome the feedback.
