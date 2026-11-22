# Lab 7 Architecture: Data Classification, Masking & BYOK Crypto-Shredding (`/data-byok`)

> **Zoom Level:** 2.5 (Lab Assembly + 3-Seat Role-Play + Cryptographic Boundary Mapping)  
> **Parent Overview:** [`0trust.dev/docs/ARCHITECTURE.md`](https://github.com/c2pig/0trust.dev/blob/main/docs/ARCHITECTURE.md)  
> **Lab Manifest:** [`lab.manifest.json`](../lab.manifest.json)  
> **Architecture Diagram:** [`docs/diagrams/data_byok_architecture.svg`](diagrams/data_byok_architecture.svg)

---

## 1. End-to-End 3-Seat Lab Architecture

```mermaid
flowchart TB
    subgraph Roles ["Archetype A: 3-Seat Role-Play (RoleSwitcherBar.tsx)"]
        S_Cust["Seat 1: Mei-Ling Tan (Customer · KYC & Privacy)"]
        S_Analyst["Seat 2: Devon Park (Data/AI Analyst · BI/LLM Workbench)"]
        S_DPO["Seat 3: Elena Rostova (DPO · KMS Console)"]
    end

    subgraph S1 ["Phase 1 (Discovery): Edge DLP Classification & Tokenization"]
        EdgeAPI["POST /api/data-byok/tokenize (Cloudflare Worker + STATE_KV 1h TTL)"]
        DLP_Secret["Gate 1: Secret Scanner (DLP-003 -> HTTP 403 BLOCK)"]
        DLP_PII["Gate 2: PII / PCI Classifier (DLP-001 PAN, DLP-002 SSN, DLP-004 NRIC/MyKad)"]
        Tokenizer["Gate 3: Deterministic SHA-256 Edge Tokenizer (tok_<type>_<8hex>)"]
        EdgeAPI --> DLP_Secret --> DLP_PII --> Tokenizer
    end

    subgraph S2 ["Phase 2 (Understanding): WebCrypto Envelope & Tokenized-Only BI/LLM"]
        DEK["Ephemeral AES-GCM-256 DEK + 96-bit CSPRNG IV"]
        AAD["AAD Binding (tenant_id|record_id|key_version)"]
        KEK["Non-Extractable Tenant KEK (AES-KW-256, extractable: false)"]
        Envelope["Encrypted Envelope in STATE_KV (lab7:byok:<sessionId>, 1h TTL)"]
        DEK --> AAD --> KEK --> Envelope
    end

    subgraph S3 ["Phase 3 & 4 (Practice & Reflection): BYOK Shredding vs. Shared-Key Trap"]
        Trap409["Shared Global KEK Trap -> HTTP 409 SHARED_KEK_COLLATERAL_BLAST_RADIUS"]
        Revoke["Revoke Per-Tenant KEK (kek-tenant-apac-01-v1 -> 0 Sibling Impact)"]
        ShredCheck["Analyst Post-Revocation Read (Scenario 7B)"]
        FailClosed["HTTP 410 CRYPTO_SHREDDED_KEY_REVOKED + Phase 4 Debrief"]
        Revoke --> ShredCheck --> FailClosed
    end

    S_Cust --> EdgeAPI
    Tokenizer --> DEK
    Envelope --> S_Analyst
    S_Cust -->|GDPR Art. 17 / PDPA Erasure Request| S_DPO
    S_DPO --> Trap409
    S_DPO --> Revoke
```

---

## 2. Distributed Repo & Module Ownership

| Lab Stage & Seat | Plain-English Purpose | Owning File / Source |
| :--- | :--- | :--- |
| **Seat 1 (`customer-kyc`) — Edge DLP & Tokenization** | Classify PII/PCI/secrets at the Cloudflare Edge; fail-closed block raw secrets (`DLP-003` → `HTTP 403`) and tokenize PII/PCI into `STATE_KV` (`1h TTL`) | `functions/api/data-byok/tokenize.ts`, `src/contracts/dataByokContract.ts`, `src/engine/dataByokEngine.ts` (aligned with `agent-governance/policies/dlp-classification.json`) |
| **Seat 2 (`ai-analyst`) — WebCrypto Envelope & BI/LLM Verification** | Encrypt tokenized records with ephemeral `AES-GCM-256` DEK wrapped by non-extractable `AES-KW-256` KEK; prove BI/LLM only receives pseudonyms and verify Scenarios `7B`, `7C`, `7D` | `src/engine/dataByokEngine.ts` (`crypto.subtle`), `src/pages/DataByokPage.tsx` |
| **Seat 3 (`dpo-kms`) — BYOK Crypto-Shredding & Shared-Key Trap** | Destroy `kek-tenant-apac-01-v1` to render all wrapped DEKs permanently unreadable while contrasting against the `HTTP 409` Shared Global KEK blast-radius trap | `functions/api/data-byok/tokenize.ts`, `src/engine/dataByokEngine.ts`, `src/pages/DataByokPage.tsx` |
| **Shared Shell & Sticky X-Ray Telemetry** | 3-Seat `RoleSwitcherBar` + sticky bottom `XRayTelemetryDrawer` (`Security Audit Feed` + `Live Decoded Proof`) | `src/components/RoleSwitcherBar.tsx`, `src/components/XRayTelemetryDrawer.tsx`, `functions/api/_middleware.ts` |

---

## 3. Security Invariants Enforced

1. **Fail-Closed Secret Blocking (`DLP-003`, Scenario 7A)**: Any payload containing raw API keys, bearer tokens, or AWS `AKIA...` credentials is blocked at the Edge DLP gate (`HTTP 403`) and never tokenized, stored in `STATE_KV`, or forwarded.
2. **Non-Extractable Tenant KEK**: Tenant KEKs are generated via `crypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, false, ['wrapKey', 'unwrapKey'])` with `extractable: false`.
3. **AAD & Integrity Binding (Scenario 7D)**: Every `AES-GCM` ciphertext is authenticated against `${tenant_id}|${record_id}|${key_version}` AAD; any tampering triggers `INTEGRITY_CHECK_FAILED`.
4. **Per-Tenant BYOK Isolation vs. Shared-Key Blast-Radius Trap**: Attempting to revoke a shared multi-tenant KEK fails closed with `HTTP 409 SHARED_KEK_COLLATERAL_BLAST_RADIUS` (protecting `14,820` records across `tenant-emea-99` and `tenant-amer-42`), whereas revoking `kek-tenant-apac-01-v1` crypto-shreds only `tenant-apac-01` (`Scenario 7B: CRYPTO_SHREDDED_KEY_REVOKED`) and rejects foreign tenant keys (`Scenario 7C: TENANT_KEY_MISMATCH`).
5. **Per-Visitor `STATE_KV` Hygiene (`1h TTL`) & End-to-End Traceability**: All Edge state under `lab7:byok:${sessionId}` expires automatically in `3600s` (`1h TTL`), and every action streams an `ObservabilitySpan` with W3C `traceparent` to the sticky `XRayTelemetryDrawer`.
6. **Model 1 Edge Hosting (`infra/terraform/`)**: Provisions the `0trust-lab-data-byok` Cloudflare Pages project and `STATE_KV` binding via `managed-infrastructure//modules/cloudflare-pages-lab` with `enable_custom_domain = false` (served behind `0trust-lab-router` at `https://lab.0trust.dev/data-byok`).

---

## Automated Hub Sync & Shell Parity
- **Standalone Route**: Served at `https://lab.0trust.dev/data-byok` via `0trust-lab-router` (`c2pig/0trust.dev`).
- **Hub Dispatch (`.github/workflows/sync-to-hub.yml`)**: Fires a `repository_dispatch` (`event_type: lab_contract_updated`) to `c2pig/0trust.dev` whenever `lab.manifest.json` or `docs/diagrams/*.svg` changes on `main`.
- **Shared Shell (`@0trust/lab-shell`)**: `RoleSwitcherBar.tsx`, `XRayTelemetryDrawer.tsx`, `src/shell/index.ts`, and `src/index.css` are kept in parity with `c2pig/0trust.dev` via `scripts/sync-lab-shell.mjs`.
