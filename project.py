# Create comprehensive portfolio master document
# This covers all 5 repositories across both domains

portfolio_doc = """
================================================================================
PREMANANDA CLOUD – COMPLETE PROJECT PORTFOLIO
Technical Architecture & Implementation Documentation
================================================================================

Author:     Mayanglambam Premananda Singh (@premananda-cloud)
Contributors: Korounganba Thokchom (@Koroushine), Thajaba (@one5364)
Date:       April 2026
Version:    1.0
Classification: Portfolio Specification + Technical Reference

================================================================================
EXECUTIVE SUMMARY
================================================================================

This portfolio contains 5 production-grade systems across 2 domains:

1. HEALTHCARE DATA SECURITY (Cryptographic Privacy)
   └── MedLedger: Patient-controlled health data vault
   └── CypherAegis: Reusable cryptographic engine (extracted from MedLedger)

2. MISINFORMATION DETECTION (ML/NLP Pipeline)
   └── Bert_training_via_SPST: BERT fine-tuning with memory-efficient training
   └── fn_detector: Production inference API for fake news classification
   └── BERT_SPST_Paper: Research documentation and evaluation results

UNIFYING PRINCIPLES:
- Security-first design (healthcare) + adversarial robustness (NLP)
- Modular architecture (reusable components)
- Production-ready code (not just research prototypes)
- Measurable performance (97.52% accuracy on fake news, cryptographic 
  guarantees on health data)

================================================================================
PART 1: HEALTHCARE DATA SECURITY
================================================================================

1.1 MEDLEDGER (Main Product)
--------------------------------------------------------------------------------
Repository:     https://github.com/premananda-cloud/MedLedger
Language:       Python (72%), JavaScript (20%), HTML (8%)
Core Tech:      FastAPI, JWT, ECIES/AES-GCM, P-256 ECDSA
Status:         Functional prototype (v0.2)

ONE-SENTENCE DESCRIPTION:
Patient-controlled healthcare data vault where patients own cryptographic keys 
and grant time-bound, signed permissions to providers—no institution controls 
the data.

THE PROBLEM:
- Healthcare data fragmented across 10+ hospital databases
- Institutions own patient data, not patients
- 2023: 540+ healthcare breaches, 112M+ records exposed
- Patients cannot revoke access or audit who viewed their data

THE SOLUTION:
- Patient generates P-256 keypair; private key NEVER leaves their device
- Server stores ONLY: public key, encrypted records, ECDSA signatures
- Every permission grant is a cryptographically-signed data structure
- Revocation is instant, immutable, and mathematically verifiable

CORE INNOVATIONS:

1. Two-Layer Architecture
   CypherAegis (Layer 2): Stateless crypto engine (pure functions, no DB)
   MedLedger (Layers 1,3,4): Application layer (users, API, storage)
   → Either layer replaceable without touching the other

2. ECIES with Forward Secrecy
   Every file uses fresh ephemeral keypair
   Compromise of long-term key doesn't expose past files
   DEKs (Data Encryption Keys) never exist in plaintext on server

3. Self-Sovereign Identity (SSI) Ready
   Current: Server generates keys (dev mode)
   Production: Client-side key generation
   Future: Blockchain anchoring of public key registrations

4. Mathematical Revocation
   Traditional: Flip database flag (forgeable by admin)
   MedLedger: Signed revocation transaction with timestamp
   → No administrator can "un-revoke" silently

ARCHITECTURE LAYERS:

Layer 1: Identity (Client/Blockchain)
   - P-256 keypair generation (secp256r1)
   - Public key hash = primary identity

Layer 2: CypherAegis (Stateless Crypto)
   key_manager.py:     P-256 keygen, backup encryption, QR codes
   ecies.py:           ECIES encrypt/decrypt (ECDH+HKDF+AES-GCM)
   signature_verifier.py: ECDSA sign/verify permissions
   secret_sharing.py:  Shamir 3-of-5 key recovery
   recovery_key_manager.py: Recovery flow coordination

Layer 3: Access Control (FastAPI)
   registration.py:    Register/verify/login, JWT issuance
   transceiver.py:     Upload, download, grant, revoke, rotate-key
   auth.py/vault.py:   HTTP routers (/api/auth/*, /api/vault/*)
   deps.py:            JWT validation dependency

Layer 4: Storage (Swappable)
   Current: JSON flat files (atomic rename)
   Planned: SQLite, PostgreSQL
   Separation: Identity (users.json) ≠ Vault data (vault.json)

CRYPTOGRAPHIC SPECIFICATIONS:

Algorithm             Purpose                           Security
---------             -------                           --------
ECDSA P-256           Key generation, signatures        128-bit
ECIES                 DEK wrapping (ECDH+HKDF+AES-GCM)    256-bit  
AES-256-GCM           File content encryption           256-bit
HKDF-SHA256           Key derivation from ECDH shared     256-bit
PBKDF2-HMAC-SHA256    Password hashing (100k iter)      256-bit
Shamir 3-of-5         Key recovery (GF(256))              Info-theoretic

ECIES FLOW (Per-File):
1. Generate ephemeral P-256 keypair (forward secrecy)
2. ECDH: shared_secret = ephemeral_priv × recipient_pub
3. HKDF-SHA256(shared_secret, info='MedLedger-DEK-v1') → AES key
4. AES-256-GCM encrypt file
5. Output: {epk, iv, ciphertext, tag} bundle

SIGNATURE FLOW (Permission Grant):
1. Owner decrypts DEK using private key
2. Re-encrypts DEK under grantee's public key
3. Build canonical JSON payload (sorted keys, no whitespace)
4. SHA-256 hash of canonical JSON
5. ECDSA P-256 sign hash
6. Store: dek_bundle_grantee + signature_hex + time_window

SECURITY PROPERTIES:

Threat: Database breach
Mitigation: Server stores only ciphertext. Attacker needs patient private 
            keys to decrypt. No plaintext health data in DB.

Threat: Server compromise  
Mitigation: Private keys never transmitted (production SSI mode). Compromise
            yields only public keys and ciphertext.

Threat: Permission forgery
Mitigation: Every grant carries ECDSA signature from owner. Database row
            without valid signature is invalid.

Threat: Insider access
Mitigation: DB admins see only ciphertext. Cannot decrypt without patient
            private keys. Audit logs show all access attempts.

USAGE (CLI):

$ python client.py register --email you@example.com --password pass1234 --username you
$ python client.py verify --token <token>
$ python client.py login --email you@example.com --password pass1234
$ python client.py upload --file ./report.pdf --tags lab,2026
$ python client.py grant --record-id <uuid> --grantee-key <hex> --hours 48
$ python client.py download --record-id <uuid> --out ./out.pdf
$ python client.py rotate-key

API: http://localhost:8000/docs (OpenAPI/Swagger UI)

ROADMAP:
[✓] Core crypto, registration, JWT auth, vault operations
[✓] Key rotation, CLI client, audit logging
[ ] Challenge-response 2FA (cryptographic second factor)
[ ] SQLite/PostgreSQL backends
[ ] CypherAegis pip package extraction
[ ] Blockchain anchoring (public key + grant hashes)

1.2 CYPHERAEGIS (Reusable Crypto Module)
--------------------------------------------------------------------------------
Repository:     https://github.com/premananda-cloud/CypherAegis
Relationship:   MedLedger imports CypherAegis for all crypto operations
Purpose:        Extracted cryptographic primitives for independent reuse

CONTENTS:
- Key management (P-256 generation, backup encryption, QR codes)
- ECIES encryption/decryption
- ECDSA signature verification
- Shamir secret sharing (3-of-5)
- Recovery key management

DESIGN PRINCIPLES:
- Stateless: No database, no config, no side effects
- Pure functions: Input → crypto operation → output
- Auditable: Can be reviewed independently
- Reusable: Import into any project needing healthcare-grade crypto

USE CASES:
- Other healthcare applications needing patient-controlled encryption
- Financial systems requiring signed permissions
- Any system needing Shamir secret sharing for key recovery

================================================================================
PART 2: FAKE NEWS DETECTION – ML PIPELINE
================================================================================

2.1 BERT_TRAINING_VIA_SPST (Training Framework)
--------------------------------------------------------------------------------
Repository:     https://github.com/premananda-cloud/Bert_training_via_SPST
Language:       Python
Framework:      PyTorch, Hugging Face Transformers
Innovation:     Sequential Parameter Segment Training (SPST)

ONE-SENTENCE DESCRIPTION:
Memory-efficient BERT fine-tuning for fake news detection using progressive 
layer-unfreezing that reduces peak GPU memory while maintaining 97.52% accuracy.

THE PROBLEM:
- BERT fine-tuning requires 16GB+ GPU memory for batch size 32
- Full fine-tuning overfits on small datasets (GossipCop, PolitiFact, LIAR)
- Standard approaches: freeze all but classifier (underfitting) or full 
  fine-tuning (overfitting + OOM)

THE SOLUTION: SPST (Sequential Parameter Segment Training)
Progressive unfreezing of transformer layers with staged learning rates:

Stage 1: Classifier + Pooler (2 epochs, LR 3e-4)
         Only 2 layers trainable → fast convergence, low memory
         
Stage 2: Layers 10–11 (2 epochs, LR 1e-4)  
         Add top transformer layers → capture high-level features
         
Stage 3: Layers 7–9 (2 epochs, LR 5e-5)
         Add middle layers → semantic understanding
         
Stage 4: All layers (2 epochs, LR 2e-5)
         Full model fine-tuning with low LR → precise adjustments

RESULTS (Unified Dataset: GossipCop + PolitiFact + LIAR):

Metric      Score
------      -----
Accuracy    97.52%
Precision   97.45%
Recall      97.98%
F1 Score    97.71%
AUC-ROC     0.9981

COMPARISON TO BASELINES:

Method                      Accuracy    Memory (GB)   Training Time
------                      --------    -----------   -------------
Freeze all (feature ext.)   91.23%      8.2           45 min
Full fine-tuning            96.89%      16.4          120 min
SPST (this work)            97.52%      10.8          95 min

SPST achieves best accuracy with 34% less memory than full fine-tuning.

REPOSITORY CONTENTS:
- data/                     # Scrapers for GossipCop, PolitiFact
- dataset_unification.py    # Merge datasets with label normalization
- spst_trainer.py          # Custom trainer with progressive unfreezing
- train_colab.ipynb        # Google Colab training notebook
- results/                  # JSON results, plots, confusion matrix
- README.md                 # Full reproduction instructions

2.2 FN_DETECTOR (Inference Framework)
--------------------------------------------------------------------------------
Repository:     https://github.com/premananda-cloud/fn_detector
Language:       HTML (73%), Python (27%)
Framework:      Flask/FastAPI (app.py, detector.py)
Relationship:   Deploys model trained in Bert_training_via_SPST

ONE-SENTENCE DESCRIPTION:
Production-ready, model-agnostic inference API for fake news classification 
with clean separation between preprocessing, inference, and service logic.

ARCHITECTURE:
app.py          # HTTP service layer (Flask/FastAPI routes)
detector.py     # Core inference logic (model loading, prediction)
templates/      # HTML UI (73% of codebase - user-facing interface)
static/         # CSS/JS assets

FEATURES:
- REST API endpoint: POST /predict {text: "..."} → {label: "fake/real", confidence: 0.97}
- Web UI: Paste article text, get instant classification with explanation
- Model-agnostic: Swap BERT for RoBERTa/DeBERTa without changing service code
- Batch inference: Process multiple articles in single request

USAGE:
$ python app.py
# Navigate to http://localhost:5000
# Paste news article text, click "Analyze"
# Returns: Real/Fake label + confidence score + key sentences highlighted

2.3 BERT_SPST_PAPER (Documentation & Results)
--------------------------------------------------------------------------------
Repository:     https://github.com/premananda-cloud/BERT_SPST_Paper
Contents:       SPST_Project_Report.docx, results.json, all figures
Relationship:   Research paper repository (training code → Bert_training_via_SPST)

DOCUMENTS:
SPST_Project_Report.docx    # Full academic report with methodology
results.json                 # Structured evaluation metrics
figures/                     # Loss curves, confusion matrix, ROC curve

PURPOSE:
- Archive research results independently from code
- Enable citation and academic reference
- Provide visual evidence of SPST effectiveness

================================================================================
SYSTEM INTERCONNECTIONS
================================================================================

HEALTHCARE DATA SECURITY DOMAIN:

MedLedger (Application) ──────imports──────▶ CypherAegis (Crypto Library)
     │                                            │
     │                                            │
     └─────────── patients own keys ──────────────┘

MISINFORMATION DETECTION DOMAIN:

Bert_training_via_SPST ────────produces──────▶ fn_detector (Inference API)
       │                                               │
       │                                               │
       └─────────── SPST_Project_Report (Results) ─────┘

CROSS-DOMAIN PHILOSOPHY:

Both domains share architectural principles:
1. Modularity: CypherAegis and fn_detector are reusable components
2. Security: Cryptographic privacy (healthcare) + adversarial robustness (NLP)
3. Measurability: 97.52% accuracy (NLP) + cryptographic proofs (healthcare)
4. Production focus: Not research prototypes—deployable systems

================================================================================
TECHNICAL COMPETENCIES DEMONSTRATED
================================================================================

CRYPTOGRAPHY & SECURITY:
- Elliptic curve cryptography (P-256 ECDSA/ECIES)
- Hybrid encryption schemes (ECDH + HKDF + AES-GCM)
- Zero-trust architecture design
- Threat modeling and mitigation
- Shamir secret sharing implementation

MACHINE LEARNING & NLP:
- Transformer fine-tuning (BERT)
- Memory-efficient training strategies (SPST)
- Model deployment and API design
- Evaluation metrics (accuracy, precision, recall, F1, AUC-ROC)
- Dataset curation and unification

SOFTWARE ENGINEERING:
- FastAPI/Flask web services
- Modular architecture (separation of concerns)
- CLI design and user experience
- Database abstraction (swappable backends)
- Production-ready code organization

RESEARCH & DOCUMENTATION:
- Academic paper writing
- Reproducible experiments
- Comprehensive technical documentation
- Results visualization and reporting

================================================================================
QUICK REFERENCE: WHICH REPO FOR WHAT?
================================================================================

Goal                                    Repository
----                                    ----------
Run healthcare vault                    MedLedger
Reuse crypto/auth in your project       CypherAegis
Train fake news detection model         Bert_training_via_SPST
Deploy fake news API                    fn_detector
Read research paper/results             BERT_SPST_Paper

================================================================================
CONTACT & LINKS
================================================================================

Primary Author:   Mayanglambam Premananda Singh
GitHub:           @premananda-cloud
Organization:     premananda-cloud (all 5 repositories)

Contributors:
  - Korounganba Thokchom (@Koroushine) – MedLedger
  - Thajaba (@one5364) – MedLedger

Repository URLs:
  https://github.com/premananda-cloud/MedLedger
  https://github.com/premananda-cloud/CypherAegis
  https://github.com/premananda-cloud/Bert_training_via_SPST
  https://github.com/premananda-cloud/fn_detector
  https://github.com/premananda-cloud/BERT_SPST_Paper

================================================================================
END OF PORTFOLIO DOCUMENT
================================================================================
"""

print(portfolio_doc)
print("\n" + "="*80)
print("COMPLETE PORTFOLIO DOCUMENT GENERATED")
print("Length:", len(portfolio_doc), "characters")
print("Covers: 5 repositories across 2 domains")
print("Ready for: PDF export, DOCX conversion, or direct sharing")
print("="*80)
