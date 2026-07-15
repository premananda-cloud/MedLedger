# MedLedger Philosophy

**Companion to:** `01-ARCHITECTURE.md` | This document explains *why*, not *how*. For implementation, see the numbered specs.

---

## We are a conduit, not a vault

MedLedger does not store your medical records. You store your medical records — on your own devices, in your own filing cabinet, wherever you already keep them. What MedLedger stores is **ciphertext it cannot read**, for a **limited time**, so that you can hand a copy to a specific doctor, specialist, or family member without emailing a PDF into the void.

If the word "vault" suggests a permanent, growing archive of your medical history sitting on our servers — that's the wrong mental model. The right mental model is closer to a **locked courier box**: you put a sealed package in, you tell the box who's allowed to open it, they come and take it out, and then the box is empty again.

This distinction drives almost every other decision in this document.

---

## The core guarantee

> We cannot be compelled to decrypt what we do not possess.

We don't hold your private keys. We don't hold your data encryption keys in plaintext. We don't hold your plaintext records. A subpoena, a breach, a rogue employee, a nation-state actor with full server access — none of them can produce your medical data from what we hold, because what we hold is mathematically useless without a key that has never touched our infrastructure.

This isn't a policy promise ("we won't look"). It's a structural one ("we can't look").

---

## Two layers, deliberately decoupled

MedLedger separates *"is this a real, rate-limited human"* from *"can this human decrypt anything."*

- **Layer 1 (Gate)** — email, password, proof-of-work, optional TOTP. Its only job is to keep the system usable: filter spam, attach an account to a real inbox, provide a session. Losing this layer is recoverable — reset your password, verify your email again.
- **Layer 2 (Keyset)** — your Ed25519/X25519 keypair, generated in your browser and never transmitted. This is your actual cryptographic identity. Losing this layer is **not recoverable**, by design. If we could recover it, we'd be a key escrow service, and the core guarantee above would be false.

We chose to keep account recovery (password reset, TOTP) *precisely because* it only ever touches Layer 1. A support burden around forgotten passwords is fine. A support pathway around recovering private keys would mean we secretly hold something we claim not to — so that pathway does not exist, full stop.

---

## Public keys are freely available on purpose

Any authenticated user can fetch any other user's public keys via `/keys/{user_id_hex}`. This is not a gap — it's the point. A public key is, definitionally, not a secret. Making key lookup easy is what lets someone request a share from you, or verify a signature you made, without a separate out-of-band exchange. The audit log — not access control — is what keeps this from being anonymous: every lookup of someone else's keys is recorded as an event, so key discovery is easy but never invisible.

What the requester needs to *do* something useful with your exchange key is still gated by you: they can look up your key, but they can't get anything sealed to it without you (or a grant on your behalf) putting a DEK bundle in front of them.

---

## Key rotation is destructive, and that's the honest choice

If you rotate your exchange key, every share that was sealed to your *old* key becomes unopenable through the server — the old DEK bundles are discarded rather than migrated forward. We do not re-wrap old grants to your new key on your behalf.

Two design paths were possible here:

1. Quietly re-encrypt old shares to the new key on rotation, so nothing is ever lost.
2. Discard what can't be re-sealed, and put the burden on the user to re-share if they still need it.

We chose (2), deliberately. Path (1) would require the server to hold something capable of re-wrapping a DEK — which means holding more than ciphertext, even briefly, even automatically. That's a bigger promise than "we store what we cannot read." Path (2) keeps the server *light* (it never accumulates a growing pile of DEK bundles it has to keep re-encrypting forever) and keeps the guarantee *simple* (nothing is ever decrypted or re-sealed server-side, ever, for any reason, including your own convenience).

The user does not lose access to their own data because of this — they hold the plaintext originals; MedLedger only ever held a temporary, targeted copy for the purpose of one transfer. Losing a stale share on rotation is losing a courier package that already should have been delivered, not losing a record.

This is also why the system is **ephemeral by default**: shares expire, `delete_on_download` defaults to true, and nothing is designed to persist past the moment it's needed. A sharing service should be judged by how well it serves the *sharing*, not by how much it accumulates.

---

## Honesty over convenience

A few places where we chose to be blunt rather than smooth over a hard edge:

- Password reset restores login. It does **not** restore vault access. The UI says so explicitly, rather than letting a relieved "I got back in" feeling paper over a locked vault.
- A lost keypair file means the account is done. The path is "delete and re-register," not a support ticket.
- Key rotation is presented with a clear warning about what it invalidates, before it happens — not discovered afterward when a share fails to decrypt.

If a security property only holds as long as no one asks an inconvenient question, it isn't a real property. MedLedger's answers to those questions are meant to be boring and consistent, even when the honest answer is "no, you cannot get that back."

---

*Document: PHILOSOPHY.md | Companion to 01-ARCHITECTURE.md, 02-SECURITY_SPEC.md*
