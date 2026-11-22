import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Database,
  FileLock2,
  KeyRound,
  Loader2,
  Lock,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  UserCheck,
  Zap
} from 'lucide-react';
import {
  DataByokAuditEvent,
  DataByokSeatId,
  DecryptVerificationResult,
  DlpEvaluationResult,
  EncryptedEnvelopeRecord,
  GateVisualState,
  LAB7_DLP_RULES,
  LAB7_SAMPLE_PRESETS,
  SharedKeyTrapResult,
  SiblingTenantSummary,
  TenantKeyState
} from '../contracts/dataByokContract';
import {
  callDataByokApi,
  createDataByokLocalSpan,
  createDataByokSessionId,
  createTraceContext,
  decryptEnvelopeWithWebCrypto,
  encryptEnvelopeWithWebCrypto,
  getTokenVaultSnapshot,
  provisionTenantKek,
  resetDataByokEngine,
  revokeTenantKek
} from '../engine/dataByokEngine';
import { RoleSeatItem, RoleSwitcherBar } from '../components/RoleSwitcherBar';
import {
  XRayDecodedProofSection,
  XRayTelemetryDrawer
} from '../components/XRayTelemetryDrawer';
import { ObservabilitySpan } from '../types';

export interface DataByokPageProps {
  onBack: () => void;
}

const TENANT_ID = 'tenant-apac-01';
const FOREIGN_TENANT_ID = 'tenant-emea-99';

const INITIAL_SIBLING_TENANTS: SiblingTenantSummary[] = [
  {
    tenant_id: 'tenant-apac-01',
    region_label: 'APAC Financial Holdings (Mei-Ling Tan)',
    key_id: 'kek-tenant-apac-01-v1',
    records_count: 1,
    status: 'ACTIVE'
  },
  {
    tenant_id: 'tenant-emea-99',
    region_label: 'EMEA Treasury Partners (Sibling Tenant)',
    key_id: 'kek-tenant-emea-99-v1',
    records_count: 8410,
    status: 'ACTIVE'
  },
  {
    tenant_id: 'tenant-amer-42',
    region_label: 'AMER Institutional Clearing (Sibling Tenant)',
    key_id: 'kek-tenant-amer-42-v1',
    records_count: 6410,
    status: 'ACTIVE'
  }
];

interface ExploredByokTraps {
  secretLeak7A: boolean;
  sharedKeyBlastRadiusTrap: boolean;
  postRevoke7B: boolean;
  crossTenant7C: boolean;
  ciphertextTamper7D: boolean;
}

const INITIAL_TRAPS: ExploredByokTraps = {
  secretLeak7A: false,
  sharedKeyBlastRadiusTrap: false,
  postRevoke7B: false,
  crossTenant7C: false,
  ciphertextTamper7D: false
};

function getGateBadge(state: GateVisualState) {
  switch (state) {
    case 'running':
      return <span className="badge badge-blue">CHECKING</span>;
    case 'passed':
      return <span className="badge badge-emerald">PASS</span>;
    case 'blocked':
      return <span className="badge badge-crimson">BLOCK</span>;
    case 'warning':
      return <span className="badge badge-amber">WARNING</span>;
    default:
      return <span className="badge badge-slate">WAITING</span>;
  }
}

function truncateMiddle(value: string, head = 18, tail = 12): string {
  if (value.length <= head + tail + 3) return value;
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

export function DataByokPage({ onBack }: DataByokPageProps) {
  const [sessionId, setSessionId] = useState<string>(() => createDataByokSessionId());
  const sessionIdRef = useRef<string>(sessionId);
  sessionIdRef.current = sessionId;

  const [activeSeat, setActiveSeat] = useState<DataByokSeatId>('customer-kyc');
  const [selectedPresetId, setSelectedPresetId] = useState<string>(LAB7_SAMPLE_PRESETS[0].id);
  const [payloadDraft, setPayloadDraft] = useState<Record<string, string>>({
    ...LAB7_SAMPLE_PRESETS[0].payload
  });
  const [traceCtx, setTraceCtx] = useState(() => createTraceContext());
  const [tenantKey, setTenantKey] = useState<TenantKeyState | null>(null);
  const [dlpResult, setDlpResult] = useState<DlpEvaluationResult | null>(null);
  const [envelope, setEnvelope] = useState<EncryptedEnvelopeRecord | null>(null);
  const [decryptResult, setDecryptResult] = useState<DecryptVerificationResult | null>(null);
  const [erasureRequested, setErasureRequested] = useState<boolean>(false);
  const [sharedKeyTrapResult, setSharedKeyTrapResult] = useState<SharedKeyTrapResult | null>(null);
  const [exploredTraps, setExploredTraps] = useState<ExploredByokTraps>(INITIAL_TRAPS);
  const [auditLog, setAuditLog] = useState<DataByokAuditEvent[]>([]);
  const [spans, setSpans] = useState<ObservabilitySpan[]>([]);

  const [animatingGate, setAnimatingGate] = useState<number>(0);
  const [isBusy, setIsBusy] = useState<boolean>(false);
  const [isAutoPlaying, setIsAutoPlaying] = useState<boolean>(false);
  const timerRefs = useRef<number[]>([]);

  const clearTimers = () => {
    timerRefs.current.forEach((id) => window.clearTimeout(id));
    timerRefs.current = [];
  };

  const recordSpan = useCallback((span: ObservabilitySpan) => {
    setSpans((prev) => [span, ...prev].slice(0, 40));
  }, []);

  const appendAudit = useCallback((entry: Omit<DataByokAuditEvent, 'id' | 'timestamp'>) => {
    const item: DataByokAuditEvent = {
      ...entry,
      id: `evt-${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
      timestamp: new Date().toISOString()
    };
    setAuditLog((prev) => [item, ...prev].slice(0, 40));
  }, []);

  useEffect(() => {
    let mounted = true;
    provisionTenantKek(TENANT_ID, 1).then((kekState) => {
      if (mounted) {
        setTenantKey(kekState);
      }
    });
    return () => {
      mounted = false;
      clearTimers();
    };
  }, []);

  const handleReset = async () => {
    clearTimers();
    setIsAutoPlaying(false);
    setIsBusy(false);
    setAnimatingGate(0);
    resetDataByokEngine();

    const freshSid = createDataByokSessionId();
    sessionIdRef.current = freshSid;
    setSessionId(freshSid);

    const freshTrace = createTraceContext();
    const freshKek = await provisionTenantKek(TENANT_ID, 1);

    setActiveSeat('customer-kyc');
    setTraceCtx(freshTrace);
    setTenantKey(freshKek);
    setSelectedPresetId(LAB7_SAMPLE_PRESETS[0].id);
    setPayloadDraft({ ...LAB7_SAMPLE_PRESETS[0].payload });
    setDlpResult(null);
    setEnvelope(null);
    setDecryptResult(null);
    setErasureRequested(false);
    setSharedKeyTrapResult(null);
    setExploredTraps(INITIAL_TRAPS);
    setSpans([]);
    setAuditLog([
      {
        id: `evt-reset-${Date.now()}`,
        timestamp: new Date().toISOString(),
        stage: 1,
        event_type: 'STATE_RESET',
        severity: 'INFO',
        title: 'Sandbox Reset & Fresh Tenant KEK Provisioned',
        detail: `Ephemeral token vault cleared. Provisioned non-extractable ${freshKek.key_id} (${freshKek.algorithm}-${freshKek.length}).`,
        correlation_id: freshTrace.correlation_id,
        traceparent: freshTrace.traceparent,
        metadata: {
          tenant_id: freshKek.tenant_id,
          key_id: freshKek.key_id,
          extractable: freshKek.extractable
        }
      }
    ]);
  };

  const handleSelectPreset = (presetId: string) => {
    const preset = LAB7_SAMPLE_PRESETS.find((p) => p.id === presetId);
    if (!preset) return;
    setSelectedPresetId(preset.id);
    setPayloadDraft({ ...preset.payload });
  };

  // ==================== Seat 1: Customer KYC & Edge DLP ====================

  const runEdgeDlpTokenize = async (overridePayload?: Record<string, string>) => {
    clearTimers();
    const targetPayload = overridePayload ?? payloadDraft;
    const currentSid = sessionIdRef.current;
    setIsBusy(true);
    setAnimatingGate(1);

    const t1 = window.setTimeout(() => setAnimatingGate(2), 180);
    const t2 = window.setTimeout(() => setAnimatingGate(3), 360);
    const t3 = window.setTimeout(async () => {
      const apiRes = await callDataByokApi<DlpEvaluationResult>({
        sessionId: currentSid,
        action: 'tokenize',
        tenantId: TENANT_ID,
        correlationId: traceCtx.correlation_id,
        traceparent: traceCtx.traceparent,
        rawPayload: targetPayload
      });

      if (sessionIdRef.current !== currentSid) return;
      recordSpan(apiRes.span);

      const result: DlpEvaluationResult = {
        correlation_id: apiRes.data.correlation_id || traceCtx.correlation_id,
        traceparent: apiRes.data.traceparent || traceCtx.traceparent,
        status: apiRes.data.status === 'BLOCK' ? 'BLOCK' : 'PASS',
        http_status: apiRes.status === 403 ? 403 : 200,
        findings: Array.isArray(apiRes.data.findings) ? apiRes.data.findings : [],
        raw_payload: apiRes.data.raw_payload || targetPayload,
        sanitized_payload: apiRes.data.sanitized_payload || {},
        blocked_reason: apiRes.data.blocked_reason,
        evaluated_at: apiRes.data.evaluated_at || new Date().toISOString()
      };

      setAnimatingGate(0);
      setIsBusy(false);
      setDlpResult(result);
      setEnvelope(null);
      setDecryptResult(null);

      if (result.status === 'BLOCK') {
        setExploredTraps((prev) => ({ ...prev, secretLeak7A: true }));
        appendAudit({
          stage: 1,
          event_type: 'DLP_SECRET_BLOCKED',
          severity: 'CRITICAL',
          title: 'Edge DLP Blocked Raw Secret Leak (HTTP 403)',
          detail:
            result.blocked_reason || 'Secret pattern DLP-003 triggered fail-closed block.',
          correlation_id: result.correlation_id,
          traceparent: result.traceparent,
          metadata: {
            http_status: result.http_status,
            findings: result.findings
          }
        });
      } else {
        appendAudit({
          stage: 1,
          event_type: 'DLP_TOKENIZED',
          severity: 'SUCCESS',
          title: `Edge DLP Tokenized ${result.findings.length} Sensitive Fields`,
          detail:
            'All PII/PCI values replaced with deterministic SHA-256 pseudonyms before AI/storage.',
          correlation_id: result.correlation_id,
          traceparent: result.traceparent,
          metadata: {
            http_status: result.http_status,
            rules_matched: Array.from(new Set(result.findings.map((f) => f.rule_id))),
            vault_size: getTokenVaultSnapshot().length
          }
        });
      }
    }, 520);

    timerRefs.current.push(t1, t2, t3);
  };

  const runEnvelopeEncryption = async (
    sanitizedOverride?: Record<string, string>,
    findingsOverride?: DlpEvaluationResult['findings'],
    kekOverride?: TenantKeyState
  ) => {
    const activeKek = kekOverride ?? tenantKey;
    const sourceDlp =
      dlpResult && dlpResult.status === 'PASS' ? dlpResult : null;
    const payloadToEncrypt = sanitizedOverride ?? sourceDlp?.sanitized_payload;
    if (!payloadToEncrypt || !activeKek) return null;

    clearTimers();
    const currentSid = sessionIdRef.current;
    setIsBusy(true);
    setAnimatingGate(1);

    return new Promise<EncryptedEnvelopeRecord | null>((resolve) => {
      const t1 = window.setTimeout(() => setAnimatingGate(2), 180);
      const t2 = window.setTimeout(() => setAnimatingGate(3), 360);
      const t3 = window.setTimeout(async () => {
        try {
          const record = await encryptEnvelopeWithWebCrypto(
            payloadToEncrypt,
            findingsOverride ?? sourceDlp?.findings ?? [],
            activeKek,
            traceCtx.correlation_id,
            traceCtx.traceparent
          );

          const storeRes = await callDataByokApi({
            sessionId: currentSid,
            action: 'store_envelope',
            tenantId: activeKek.tenant_id,
            correlationId: traceCtx.correlation_id,
            traceparent: traceCtx.traceparent,
            envelope: record
          });

          if (sessionIdRef.current !== currentSid) {
            resolve(null);
            return;
          }
          recordSpan(storeRes.span);

          setAnimatingGate(0);
          setIsBusy(false);
          setEnvelope(record);
          setDecryptResult(null);
          appendAudit({
            stage: 2,
            event_type: 'ENVELOPE_ENCRYPTED',
            severity: 'SUCCESS',
            title: `WebCrypto Envelope Encrypted & Stored (${record.record_id})`,
            detail: `Ephemeral AES-GCM-256 DEK encrypted payload with 96-bit IV + AAD (${record.aad_text}) and was wrapped by non-extractable ${record.key_id}.`,
            correlation_id: record.correlation_id,
            traceparent: record.traceparent,
            metadata: {
              record_id: record.record_id,
              aad: record.aad_text,
              dek_algorithm: record.dek_algorithm,
              kek_algorithm: record.kek_algorithm,
              kv_ttl_seconds: 3600
            }
          });
          resolve(record);
        } catch (err) {
          setAnimatingGate(0);
          setIsBusy(false);
          appendAudit({
            stage: 2,
            event_type: 'CRYPTO_SHRED_VERIFIED',
            severity: 'CRITICAL',
            title: 'Encryption Blocked: Tenant KEK Revoked',
            detail: err instanceof Error ? err.message : 'Active Tenant KEK required.',
            correlation_id: traceCtx.correlation_id,
            traceparent: traceCtx.traceparent,
            metadata: { tenant_id: activeKek.tenant_id, status: activeKek.status }
          });
          resolve(null);
        }
      }, 520);

      timerRefs.current.push(t1, t2, t3);
    });
  };

  const handleRequestRightToErasure = () => {
    setErasureRequested(true);
    const span = createDataByokLocalSpan({
      sessionId: sessionIdRef.current,
      method: 'POST',
      path: '/api/data-byok/erasure-request (gdpr-art-17)',
      status: 202,
      latencyMs: 4,
      traceparent: traceCtx.traceparent,
      responseSummary: {
        status: 'ERASURE_REQUEST_QUEUED',
        regulation: 'GDPR Art. 17 / PDPA Right-to-Erasure',
        tenant_id: TENANT_ID,
        target_key_id: tenantKey?.key_id || 'kek-tenant-apac-01-v1',
        assigned_seat: 'dpo-kms (Elena Rostova)'
      }
    });
    recordSpan(span);
    appendAudit({
      stage: 3,
      event_type: 'ERASURE_REQUESTED',
      severity: 'WARN',
      title: 'Customer Right-to-Erasure Request Submitted (GDPR Art. 17 / PDPA)',
      detail: `Mei-Ling Tan requested immediate cryptographic erasure of all records for ${TENANT_ID}. Routed to DPO KMS Console.`,
      correlation_id: traceCtx.correlation_id,
      traceparent: traceCtx.traceparent,
      metadata: {
        tenant_id: TENANT_ID,
        key_id: tenantKey?.key_id,
        record_id: envelope?.record_id
      }
    });
  };

  // ==================== Seat 2: Data/AI Analyst Actions ====================

  const runDecryptVerification = async (
    mode: 'NORMAL' | 'POST_REVOKE_7B' | 'CROSS_TENANT' | 'TAMPER'
  ) => {
    if (!envelope || !tenantKey) return;
    clearTimers();
    const currentSid = sessionIdRef.current;
    setIsBusy(true);
    setAnimatingGate(1);

    let effectiveKeyState = tenantKey;
    // If user clicks Scenario 7B directly while KEK is still ACTIVE, revoke KEK first so Scenario 7B is 1-click verifiable
    if (mode === 'POST_REVOKE_7B' && tenantKey.status === 'ACTIVE') {
      const revoked = revokeTenantKek(tenantKey);
      effectiveKeyState = revoked;
      setTenantKey(revoked);
      const revRes = await callDataByokApi({
        sessionId: currentSid,
        action: 'revoke_kek',
        tenantId: TENANT_ID,
        correlationId: traceCtx.correlation_id,
        traceparent: traceCtx.traceparent
      });
      recordSpan(revRes.span);
      appendAudit({
        stage: 3,
        event_type: 'KEK_REVOKED',
        severity: 'WARN',
        title: `Tenant BYOK Key Revoked (${revoked.key_id})`,
        detail:
          'Non-extractable AES-KW KEK permanently destroyed from memory & STATE_KV before Scenario 7B read probe.',
        correlation_id: traceCtx.correlation_id,
        traceparent: traceCtx.traceparent,
        metadata: {
          tenant_id: revoked.tenant_id,
          key_id: revoked.key_id,
          revoked_at: revoked.revoked_at
        }
      });
    }

    const t1 = window.setTimeout(() => setAnimatingGate(2), 180);
    const t2 = window.setTimeout(() => setAnimatingGate(3), 360);
    const t3 = window.setTimeout(async () => {
      const start = performance.now();
      const res = await decryptEnvelopeWithWebCrypto(
        envelope,
        effectiveKeyState,
        traceCtx.correlation_id,
        traceCtx.traceparent,
        {
          crossTenantId: mode === 'CROSS_TENANT' ? FOREIGN_TENANT_ID : undefined,
          tamperCiphertext: mode === 'TAMPER'
        }
      );

      const httpStatus = res.ok
        ? 200
        : res.status === 'CRYPTO_SHREDDED_KEY_REVOKED'
          ? 410
          : 403;

      const span = createDataByokLocalSpan({
        sessionId: currentSid,
        method: 'POST',
        path: `/api/data-byok/decrypt-verify (${mode.toLowerCase()})`,
        status: httpStatus,
        latencyMs: Math.round(performance.now() - start) + 3,
        traceparent: traceCtx.traceparent,
        responseSummary: {
          status: res.status,
          ok: res.ok,
          error_code: res.error_code,
          error_detail: res.error_detail,
          record_id: envelope.record_id,
          tenant_id: envelope.tenant_id,
          decrypted_fields: res.decrypted_payload ? Object.keys(res.decrypted_payload) : []
        }
      });
      recordSpan(span);

      setAnimatingGate(0);
      setIsBusy(false);
      setDecryptResult(res);

      if (res.ok) {
        appendAudit({
          stage: 3,
          event_type: 'DECRYPT_SUCCEEDED',
          severity: 'SUCCESS',
          title: `Analyst Query Decrypted Tokenized Record (${envelope.record_id})`,
          detail:
            'Active Tenant KEK unwrapped DEK. BI/LLM workbench received tokenized pseudonyms only — raw NRIC/SSN/PAN never exposed.',
          correlation_id: res.correlation_id,
          traceparent: res.traceparent,
          metadata: { record_id: envelope.record_id, status: res.status }
        });
      } else if (res.status === 'CRYPTO_SHREDDED_KEY_REVOKED') {
        setExploredTraps((prev) => ({ ...prev, postRevoke7B: true }));
        appendAudit({
          stage: 3,
          event_type: 'CRYPTO_SHRED_VERIFIED',
          severity: 'CRITICAL',
          title: 'Scenario 7B Verified: CRYPTO_SHREDDED_KEY_REVOKED (HTTP 410)',
          detail:
            res.error_detail || 'Unwrap denied; ciphertext is permanently unreadable.',
          correlation_id: res.correlation_id,
          traceparent: res.traceparent,
          metadata: { error_code: res.error_code, record_id: envelope.record_id }
        });
      } else if (res.status === 'TENANT_KEY_MISMATCH') {
        setExploredTraps((prev) => ({ ...prev, crossTenant7C: true }));
        appendAudit({
          stage: 3,
          event_type: 'TENANT_MISMATCH_BLOCKED',
          severity: 'CRITICAL',
          title: 'Scenario 7C Blocked: TENANT_KEY_MISMATCH (HTTP 403)',
          detail: res.error_detail || 'Foreign tenant KEK cannot unwrap DEK.',
          correlation_id: res.correlation_id,
          traceparent: res.traceparent,
          metadata: {
            error_code: res.error_code,
            attempted_tenant: FOREIGN_TENANT_ID,
            record_tenant: envelope.tenant_id
          }
        });
      } else {
        setExploredTraps((prev) => ({ ...prev, ciphertextTamper7D: true }));
        appendAudit({
          stage: 3,
          event_type: 'INTEGRITY_CHECK_FAILED',
          severity: 'CRITICAL',
          title: 'Scenario 7D Tamper Detected: INTEGRITY_CHECK_FAILED (HTTP 403)',
          detail:
            res.error_detail ||
            'AES-GCM authentication tag rejected modified ciphertext.',
          correlation_id: res.correlation_id,
          traceparent: res.traceparent,
          metadata: { error_code: res.error_code, record_id: envelope.record_id }
        });
      }
    }, 520);

    timerRefs.current.push(t1, t2, t3);
  };

  // ==================== Seat 3: DPO KMS Console Actions ====================

  const handleRevokePerTenantKek = async () => {
    if (!tenantKey || tenantKey.status === 'REVOKED') return;
    setIsBusy(true);
    const currentSid = sessionIdRef.current;

    const revoked = revokeTenantKek(tenantKey);
    setTenantKey(revoked);
    setDecryptResult(null);

    const apiRes = await callDataByokApi({
      sessionId: currentSid,
      action: 'revoke_kek',
      tenantId: TENANT_ID,
      correlationId: traceCtx.correlation_id,
      traceparent: traceCtx.traceparent
    });

    if (sessionIdRef.current !== currentSid) return;
    recordSpan(apiRes.span);
    setIsBusy(false);

    appendAudit({
      stage: 3,
      event_type: 'KEK_REVOKED',
      severity: 'WARN',
      title: `Per-Tenant BYOK Key Revoked (${revoked.key_id}) — 0 Sibling Tenants Impacted`,
      detail:
        'Non-extractable AES-KW KEK permanently destroyed from memory & STATE_KV. All wrapped DEKs for tenant-apac-01 are mathematically unrecoverable while sibling tenants remain ACTIVE.',
      correlation_id: traceCtx.correlation_id,
      traceparent: traceCtx.traceparent,
      metadata: {
        tenant_id: revoked.tenant_id,
        key_id: revoked.key_id,
        revoked_at: revoked.revoked_at,
        sibling_tenants_impacted: 0
      }
    });
  };

  const handleTriggerSharedKeyTrap = async () => {
    setIsBusy(true);
    const currentSid = sessionIdRef.current;
    const apiRes = await callDataByokApi<SharedKeyTrapResult>({
      sessionId: currentSid,
      action: 'revoke_shared_kek_trap',
      tenantId: TENANT_ID,
      correlationId: traceCtx.correlation_id,
      traceparent: traceCtx.traceparent
    });

    if (sessionIdRef.current !== currentSid) return;
    recordSpan(apiRes.span);
    setIsBusy(false);

    const trapData: SharedKeyTrapResult = {
      status: 'SHARED_KEY_BLAST_RADIUS_BLOCKED',
      http_status: 409,
      error_code: 'SHARED_KEK_COLLATERAL_BLAST_RADIUS',
      target_tenant: apiRes.data.target_tenant || TENANT_ID,
      collateral_tenants_affected: apiRes.data.collateral_tenants_affected || [
        'tenant-emea-99',
        'tenant-amer-42'
      ],
      collateral_records_at_risk: apiRes.data.collateral_records_at_risk || 14820,
      invariant: 'BYOK_PER_TENANT_KEK_ISOLATION',
      message:
        apiRes.data.message ||
        'Blast-Radius Trap Triggered: Revoking a Shared Global KEK to erase one customer destroys data for 2 innocent sibling tenants (tenant-emea-99, tenant-amer-42). Enforce per-tenant AES-KW-256 KEK isolation with tenant-bound AAD.',
      correlation_id: apiRes.data.correlation_id || traceCtx.correlation_id,
      traceparent: apiRes.data.traceparent || traceCtx.traceparent,
      triggered_at: apiRes.data.triggered_at || new Date().toISOString()
    };

    setSharedKeyTrapResult(trapData);
    setExploredTraps((prev) => ({ ...prev, sharedKeyBlastRadiusTrap: true }));

    appendAudit({
      stage: 3,
      event_type: 'SHARED_KEY_BLAST_RADIUS_TRAPPED',
      severity: 'CRITICAL',
      title: 'Shared Global KEK Trap Blocked (HTTP 409 SHARED_KEK_COLLATERAL_BLAST_RADIUS)',
      detail: trapData.message,
      correlation_id: trapData.correlation_id,
      traceparent: trapData.traceparent,
      metadata: {
        http_status: 409,
        error_code: trapData.error_code,
        collateral_tenants_affected: trapData.collateral_tenants_affected,
        collateral_records_at_risk: trapData.collateral_records_at_risk
      }
    });
  };

  // ==================== Guided 3-Seat Walkthrough ====================

  const handleGuidedWalkthrough = async () => {
    clearTimers();
    setIsAutoPlaying(true);
    setIsBusy(true);
    resetDataByokEngine();

    const freshSid = createDataByokSessionId();
    sessionIdRef.current = freshSid;
    setSessionId(freshSid);

    const freshTrace = createTraceContext();
    const freshKek = await provisionTenantKek(TENANT_ID, 1);
    const seedPayload = { ...LAB7_SAMPLE_PRESETS[0].payload };

    setActiveSeat('customer-kyc');
    setTraceCtx(freshTrace);
    setTenantKey(freshKek);
    setSelectedPresetId(LAB7_SAMPLE_PRESETS[0].id);
    setPayloadDraft(seedPayload);
    setEnvelope(null);
    setDecryptResult(null);
    setErasureRequested(true);
    setSharedKeyTrapResult(null);

    // Step 1: Seat 1 Edge DLP Tokenize + WebCrypto Envelope Encrypt
    const dlpApi = await callDataByokApi<DlpEvaluationResult>({
      sessionId: freshSid,
      action: 'tokenize',
      tenantId: TENANT_ID,
      correlationId: freshTrace.correlation_id,
      traceparent: freshTrace.traceparent,
      rawPayload: seedPayload
    });
    recordSpan(dlpApi.span);

    const dlp: DlpEvaluationResult = {
      correlation_id: dlpApi.data.correlation_id || freshTrace.correlation_id,
      traceparent: dlpApi.data.traceparent || freshTrace.traceparent,
      status: 'PASS',
      http_status: 200,
      findings: dlpApi.data.findings || [],
      raw_payload: seedPayload,
      sanitized_payload: dlpApi.data.sanitized_payload || {},
      evaluated_at: new Date().toISOString()
    };
    setDlpResult(dlp);

    const env = await encryptEnvelopeWithWebCrypto(
      dlp.sanitized_payload,
      dlp.findings,
      freshKek,
      freshTrace.correlation_id,
      freshTrace.traceparent
    );
    const storeApi = await callDataByokApi({
      sessionId: freshSid,
      action: 'store_envelope',
      tenantId: TENANT_ID,
      correlationId: freshTrace.correlation_id,
      traceparent: freshTrace.traceparent,
      envelope: env
    });
    recordSpan(storeApi.span);
    setEnvelope(env);

    appendAudit({
      stage: 1,
      event_type: 'DLP_TOKENIZED',
      severity: 'SUCCESS',
      title: `Walkthrough Seat 1: Tokenized ${dlp.findings.length} Fields & Encrypted Envelope (${env.record_id})`,
      detail: 'Customer PII/PCI tokenized at Edge and wrapped with non-extractable Tenant KEK.',
      correlation_id: freshTrace.correlation_id,
      traceparent: freshTrace.traceparent,
      metadata: { record_id: env.record_id, aad: env.aad_text }
    });

    const t1 = window.setTimeout(async () => {
      // Step 2: Seat 3 DPO tests Shared-Key Blast-Radius Trap & Revokes Per-Tenant KEK
      setActiveSeat('dpo-kms');
      const trapApi = await callDataByokApi<SharedKeyTrapResult>({
        sessionId: freshSid,
        action: 'revoke_shared_kek_trap',
        tenantId: TENANT_ID,
        correlationId: freshTrace.correlation_id,
        traceparent: freshTrace.traceparent
      });
      recordSpan(trapApi.span);
      setSharedKeyTrapResult({
        status: 'SHARED_KEY_BLAST_RADIUS_BLOCKED',
        http_status: 409,
        error_code: 'SHARED_KEK_COLLATERAL_BLAST_RADIUS',
        target_tenant: TENANT_ID,
        collateral_tenants_affected: ['tenant-emea-99', 'tenant-amer-42'],
        collateral_records_at_risk: 14820,
        invariant: 'BYOK_PER_TENANT_KEK_ISOLATION',
        message:
          'Blast-Radius Trap Triggered: Revoking a Shared Global KEK to erase one customer destroys data for 2 innocent sibling tenants (tenant-emea-99, tenant-amer-42). Enforce per-tenant AES-KW-256 KEK isolation with tenant-bound AAD.',
        correlation_id: freshTrace.correlation_id,
        traceparent: freshTrace.traceparent,
        triggered_at: new Date().toISOString()
      });

      const revoked = revokeTenantKek(freshKek);
      setTenantKey(revoked);
      const revApi = await callDataByokApi({
        sessionId: freshSid,
        action: 'revoke_kek',
        tenantId: TENANT_ID,
        correlationId: freshTrace.correlation_id,
        traceparent: freshTrace.traceparent
      });
      recordSpan(revApi.span);

      const t2 = window.setTimeout(async () => {
        // Step 3: Seat 2 Analyst verifies CRYPTO_SHREDDED_KEY_REVOKED
        setActiveSeat('ai-analyst');
        const shredCheck = await decryptEnvelopeWithWebCrypto(
          env,
          revoked,
          freshTrace.correlation_id,
          freshTrace.traceparent
        );
        setDecryptResult(shredCheck);
        setExploredTraps((prev) => ({
          ...prev,
          sharedKeyBlastRadiusTrap: true,
          postRevoke7B: true
        }));

        const span = createDataByokLocalSpan({
          sessionId: freshSid,
          method: 'POST',
          path: '/api/data-byok/decrypt-verify (post_revoke_7b)',
          status: 410,
          latencyMs: 5,
          traceparent: freshTrace.traceparent,
          responseSummary: {
            status: shredCheck.status,
            error_code: shredCheck.error_code,
            record_id: env.record_id
          }
        });
        recordSpan(span);

        appendAudit({
          stage: 3,
          event_type: 'CRYPTO_SHRED_VERIFIED',
          severity: 'CRITICAL',
          title: 'Walkthrough Seat 2: Crypto-Shredding Verified (HTTP 410)',
          detail: shredCheck.error_detail || 'CRYPTO_SHREDDED_KEY_REVOKED',
          correlation_id: freshTrace.correlation_id,
          traceparent: freshTrace.traceparent,
          metadata: { error_code: shredCheck.error_code }
        });
        setIsAutoPlaying(false);
        setIsBusy(false);
      }, 750);
      timerRefs.current.push(t2);
    }, 750);
    timerRefs.current.push(t1);
  };

  // ==================== Derived Badges & Gate Visuals ====================

  const isKekRevoked = tenantKey?.status === 'REVOKED';
  const stage1Done = dlpResult?.status === 'PASS';
  const stage2Done = envelope !== null;
  const stage3Done =
    decryptResult?.status === 'CRYPTO_SHREDDED_KEY_REVOKED' || isKekRevoked;

  const customerBadge: RoleSeatItem<DataByokSeatId>['badge'] = isKekRevoked
    ? { text: 'Crypto-Shredded', tone: 'crimson' }
    : erasureRequested
      ? { text: 'Erasure Pending', tone: 'amber', pulse: true }
      : envelope
        ? { text: 'Encrypted', tone: 'emerald' }
        : dlpResult?.status === 'PASS'
          ? { text: 'PII Tokenized', tone: 'blue' }
          : dlpResult?.status === 'BLOCK'
            ? { text: 'Secret Blocked (403)', tone: 'crimson', pulse: true }
            : { text: 'Onboarding', tone: 'neutral' };

  const analystBadge: RoleSeatItem<DataByokSeatId>['badge'] =
    isKekRevoked || (decryptResult && !decryptResult.ok)
      ? { text: '403 Shredded / Blocked', tone: 'crimson', pulse: true }
      : decryptResult?.ok || envelope
        ? { text: 'Tokenized Read-Only', tone: 'emerald' }
        : { text: 'Waiting for Data', tone: 'neutral' };

  const dpoBadge: RoleSeatItem<DataByokSeatId>['badge'] = isKekRevoked
    ? { text: 'KEK Revoked (Shredded)', tone: 'crimson' }
    : erasureRequested
      ? { text: '● 1 Erasure Req', tone: 'amber', pulse: true }
      : { text: 'KEK Active · v1', tone: 'emerald' };

  const seats: RoleSeatItem<DataByokSeatId>[] = [
    {
      id: 'customer-kyc',
      name: 'Mei-Ling Tan',
      roleLabel: 'Customer · KYC & Privacy',
      appLabel: 'FinCore KYC & Privacy Center',
      avatarInitials: 'MT',
      badge: customerBadge
    },
    {
      id: 'ai-analyst',
      name: 'Devon Park',
      roleLabel: 'Data/AI Analyst · BI/LLM',
      appLabel: 'BI & LLM Risk Workbench',
      avatarInitials: 'DP',
      badge: analystBadge
    },
    {
      id: 'dpo-kms',
      name: 'Elena Rostova',
      roleLabel: 'DPO · KMS Console',
      appLabel: 'BYOK Key Management & Shredder',
      avatarInitials: 'ER',
      badge: dpoBadge
    }
  ];

  const getStage1GateState = (gate: 1 | 2 | 3): GateVisualState => {
    if (activeSeat === 'customer-kyc' && animatingGate === gate) return 'running';
    if (activeSeat === 'customer-kyc' && animatingGate > gate) return 'passed';
    if (!dlpResult) return 'pending';
    if (dlpResult.status === 'BLOCK') {
      return gate === 1 ? 'blocked' : 'pending';
    }
    return 'passed';
  };

  const getStage3GateState = (gate: 1 | 2 | 3): GateVisualState => {
    if (activeSeat === 'ai-analyst' && animatingGate === gate) return 'running';
    if (activeSeat === 'ai-analyst' && animatingGate > gate) return 'passed';
    if (!decryptResult) return 'pending';
    if (decryptResult.ok) return 'passed';
    if (decryptResult.status === 'CRYPTO_SHREDDED_KEY_REVOKED') {
      return gate === 1 ? 'blocked' : 'pending';
    }
    if (decryptResult.status === 'TENANT_KEY_MISMATCH') {
      if (gate === 1) return 'passed';
      if (gate === 2) return 'blocked';
      return 'pending';
    }
    if (gate < 3) return 'passed';
    return 'blocked';
  };

  const trapChecklist = [
    {
      key: 'secretLeak7A',
      label: 'Scenario 7A: Unmasked Secret Leak (api_key / AKIA -> HTTP 403 DLP-003 BLOCK)',
      tested: exploredTraps.secretLeak7A
    },
    {
      key: 'sharedKeyTrap',
      label: 'Shared Global KEK Blast-Radius Trap (HTTP 409 SHARED_KEK_COLLATERAL_BLAST_RADIUS)',
      tested: exploredTraps.sharedKeyBlastRadiusTrap
    },
    {
      key: 'postRevoke7B',
      label: 'Scenario 7B: Post-Revocation Read (HTTP 410 CRYPTO_SHREDDED_KEY_REVOKED)',
      tested: exploredTraps.postRevoke7B
    },
    {
      key: 'crossTenant7C',
      label: 'Scenario 7C: Cross-Tenant Key Mismatch (tenant-emea-99 KEK -> TENANT_KEY_MISMATCH)',
      tested: exploredTraps.crossTenant7C
    },
    {
      key: 'ciphertextTamper7D',
      label: 'Scenario 7D: Ciphertext / AAD Tamper (Bit-Flip -> AES-GCM INTEGRITY_CHECK_FAILED)',
      tested: exploredTraps.ciphertextTamper7D
    }
  ];

  const testedTrapCount = trapChecklist.filter((item) => item.tested).length;

  const siblingTenants: SiblingTenantSummary[] = INITIAL_SIBLING_TENANTS.map((t) =>
    t.tenant_id === TENANT_ID
      ? { ...t, status: isKekRevoked ? 'REVOKED' : 'ACTIVE' }
      : t
  );

  const decodedProofSections: XRayDecodedProofSection[] = [
    {
      id: 'edge-dlp-proof',
      label: '1. Edge DLP Classification & Token Vault (/api/data-byok/tokenize)',
      payload: {
        correlation_id: dlpResult?.correlation_id ?? traceCtx.correlation_id,
        traceparent: dlpResult?.traceparent ?? traceCtx.traceparent,
        dlp_status: dlpResult?.status ?? 'IDLE',
        http_status: dlpResult?.http_status ?? null,
        rules_enforced: LAB7_DLP_RULES.map((r) => `${r.id}:${r.name}:${r.action}`),
        findings: dlpResult?.findings ?? [],
        sanitized_payload: dlpResult?.sanitized_payload ?? null
      }
    },
    {
      id: 'webcrypto-envelope-proof',
      label: '2. WebCrypto Envelope (AES-GCM-256 DEK + AES-KW-256 KEK)',
      payload: envelope
        ? {
            record_id: envelope.record_id,
            tenant_id: envelope.tenant_id,
            key_id: envelope.key_id,
            dek_algorithm: `${envelope.dek_algorithm}-${envelope.dek_length}`,
            kek_algorithm: `${envelope.kek_algorithm}-256 (extractable: false)`,
            aad_text: envelope.aad_text,
            iv_b64: envelope.iv_b64,
            wrapped_dek_b64: isKekRevoked
              ? '[SHREDDED_UNWRAPPABLE_WITHOUT_KEK]'
              : envelope.wrapped_dek_b64,
            ciphertext_b64: truncateMiddle(envelope.ciphertext_b64, 28, 16)
          }
        : { status: 'NOT_ENCRYPTED_YET', info: 'Tokenize & encrypt in Seat 1 to inspect envelope.' }
    },
    {
      id: 'byok-kms-proof',
      label: '3. BYOK Key Hierarchy & Crypto-Shredding Verification',
      payload: {
        tenant_kek_state: tenantKey,
        erasure_requested: erasureRequested,
        sibling_tenant_isolation: siblingTenants,
        decrypt_verification: decryptResult ?? 'No decryption probe executed yet'
      }
    },
    {
      id: 'shared-key-trap-proof',
      label: '4. Shared Key Blast-Radius Trap & Security Audit Events',
      payload: {
        shared_key_blast_radius_trap:
          sharedKeyTrapResult ?? 'Not triggered yet (test in Seat 3 DPO KMS Console)',
        recent_audit_events: auditLog.slice(0, 5)
      }
    }
  ];

  return (
    <div className="lab-shell">
      {/* Invariant 1: Capability-First Header */}
      <header className="lab-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
          <button
            type="button"
            className="btn btn-sm"
            onClick={onBack}
            aria-label="All Labs"
          >
            <ArrowLeft size={13} />
            <span>All Labs</span>
          </button>
          <span
            style={{
              fontSize: '14.5px',
              fontWeight: 700,
              letterSpacing: '-0.015em',
              color: 'var(--text-primary)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis'
            }}
          >
            Data Classification, Masking &amp; BYOK Crypto-Shredding
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '4px 10px',
              borderRadius: '6px',
              backgroundColor: 'var(--bg-elevated)',
              border: '1px solid var(--border-subtle)',
              fontSize: '11.5px',
              fontWeight: 600,
              color: 'var(--text-secondary)'
            }}
          >
            <Zap size={12} color="#059669" />
            <span>$0.00 Guided Sandbox · Edge DLP + WebCrypto</span>
          </span>

          <button
            type="button"
            className="btn btn-emerald btn-sm"
            onClick={() => void handleGuidedWalkthrough()}
            disabled={isAutoPlaying}
          >
            <Play size={12} />
            <span>
              {isAutoPlaying ? 'Running 3-Seat Walkthrough…' : 'Guided Walkthrough'}
            </span>
          </button>

          <button
            type="button"
            className="btn btn-sm"
            onClick={() => void handleReset()}
            aria-label="Reset lab session"
          >
            <RotateCcw size={12} />
            <span>↺ Reset</span>
          </button>
        </div>
      </header>

      {/* Invariant 3: Natural Document Flow Workspace */}
      <main className="lab-workspace">
        {/* Archetype A: 3-Seat Role Switcher Bar */}
        <RoleSwitcherBar
          seats={seats}
          activeSeatId={activeSeat}
          onSelectSeat={(seatId) => setActiveSeat(seatId)}
          ariaLabel="Data Classification & BYOK 3-Seat Role Switcher"
        />

        {/* Invariant 2: 4-Phase Cognitive Arc Status Strip */}
        <section
          aria-label="4-Phase Cognitive Arc"
          style={{
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-md)',
            padding: '10px 14px',
            marginBottom: '14px',
            boxShadow: 'var(--shadow-sm)',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '10px'
          }}
        >
          <button
            type="button"
            onClick={() => setActiveSeat('customer-kyc')}
            style={{
              textAlign: 'left',
              padding: '8px 10px',
              borderRadius: '6px',
              border: `1px solid ${
                activeSeat === 'customer-kyc'
                  ? 'var(--accent-primary-border)'
                  : 'var(--border-subtle)'
              }`,
              backgroundColor:
                activeSeat === 'customer-kyc'
                  ? 'var(--accent-primary-dim)'
                  : 'var(--bg-canvas)',
              cursor: 'pointer',
              fontFamily: 'inherit'
            }}
          >
            <div style={{ fontSize: '10.5px', fontWeight: 700, color: '#1d4ed8', textTransform: 'uppercase' }}>
              Phase 1 · Discovery {stage1Done && stage2Done ? '✓' : ''}
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Seat 1: Customer KYC &amp; Edge DLP
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Block secrets (403), tokenize PII/PCI &amp; wrap DEK
            </div>
          </button>

          <button
            type="button"
            onClick={() => setActiveSeat('ai-analyst')}
            style={{
              textAlign: 'left',
              padding: '8px 10px',
              borderRadius: '6px',
              border: `1px solid ${
                activeSeat === 'ai-analyst'
                  ? 'var(--accent-primary-border)'
                  : 'var(--border-subtle)'
              }`,
              backgroundColor:
                activeSeat === 'ai-analyst'
                  ? 'var(--accent-primary-dim)'
                  : 'var(--bg-canvas)',
              cursor: 'pointer',
              fontFamily: 'inherit'
            }}
          >
            <div style={{ fontSize: '10.5px', fontWeight: 700, color: '#059669', textTransform: 'uppercase' }}>
              Phase 2 · Understanding {decryptResult?.ok ? '✓' : ''}
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Seat 2: BI &amp; LLM Risk Workbench
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Verify AI sees pseudonyms only + Red-Team 7B/7C/7D
            </div>
          </button>

          <button
            type="button"
            onClick={() => setActiveSeat('dpo-kms')}
            style={{
              textAlign: 'left',
              padding: '8px 10px',
              borderRadius: '6px',
              border: `1px solid ${
                activeSeat === 'dpo-kms'
                  ? 'var(--accent-primary-border)'
                  : 'var(--border-subtle)'
              }`,
              backgroundColor:
                activeSeat === 'dpo-kms'
                  ? 'var(--accent-primary-dim)'
                  : 'var(--bg-canvas)',
              cursor: 'pointer',
              fontFamily: 'inherit'
            }}
          >
            <div style={{ fontSize: '10.5px', fontWeight: 700, color: '#d97706', textTransform: 'uppercase' }}>
              Phase 3 · Practice {isKekRevoked ? '✓' : ''}
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Seat 3: DPO BYOK KMS &amp; Shredder
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              Per-Tenant KEK shred vs. Shared-Key Blast-Radius Trap
            </div>
          </button>

          <div
            style={{
              padding: '8px 10px',
              borderRadius: '6px',
              border: `1px solid ${
                stage3Done ? 'var(--accent-emerald-border)' : 'var(--border-subtle)'
              }`,
              backgroundColor: stage3Done
                ? 'var(--accent-emerald-dim)'
                : 'var(--bg-canvas)'
            }}
          >
            <div
              style={{
                fontSize: '10.5px',
                fontWeight: 700,
                color: stage3Done ? 'var(--accent-emerald-ink)' : 'var(--text-muted)',
                textTransform: 'uppercase'
              }}
            >
              Phase 4 · Reflection {stage3Done ? '✓ UNLOCKED' : '· Pending Shred'}
            </div>
            <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Traps Explored: {testedTrapCount} / {trapChecklist.length}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
              {stage3Done
                ? 'Scroll down for architectural debrief'
                : 'Revoke KEK in Seat 3 & verify in Seat 2'}
            </div>
          </div>
        </section>

        {/* ==================== SEAT 1: CUSTOMER · KYC & PRIVACY ==================== */}
        {activeSeat === 'customer-kyc' && (
          <section
            aria-label="Mei-Ling Tan FinCore KYC and Privacy Center"
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
              boxShadow: 'var(--shadow-sm)',
              overflow: 'hidden',
              marginBottom: '16px'
            }}
          >
            <div
              style={{
                padding: '12px 18px',
                borderBottom: '1px solid var(--border-subtle)',
                backgroundColor: 'var(--bg-canvas)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '10px',
                flexWrap: 'wrap'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <UserCheck size={16} color="#2563eb" />
                <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  FinCore KYC &amp; Privacy Center · Customer Onboarding &amp; Right-to-Erasure
                </span>
                <span className="mono" style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                  Tenant: {TENANT_ID}
                </span>
              </div>

              <span className={`badge ${isKekRevoked ? 'badge-crimson' : 'badge-emerald'}`}>
                {isKekRevoked
                  ? 'KEK REVOKED (CRYPTO-SHREDDED)'
                  : `KEK ACTIVE · ${tenantKey?.key_id ?? 'kek-tenant-apac-01-v1'}`}
              </span>
            </div>

            <div style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                  gap: '18px',
                  alignItems: 'start'
                }}
              >
                {/* Left Column: Customer KYC Form & Red-Team 7A */}
                <div
                  style={{
                    padding: '16px',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-subtle)',
                    backgroundColor: 'var(--bg-canvas)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '12px'
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontSize: '11px',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        letterSpacing: '0.06em',
                        color: '#1d4ed8'
                      }}
                    >
                      Phase 1 · Discovery · Edge DLP Boundary
                    </div>
                    <h2 style={{ fontSize: '15.5px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                      Submit Customer KYC &amp; Settlement Payload
                    </h2>
                    <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                      Cloudflare Edge Worker (<code>POST /api/data-byok/tokenize</code>) scans every field before AI inference or storage: blocking raw secrets (<code>DLP-003</code>) and replacing NRIC, SSN, and PCI PAN with deterministic SHA-256 tokens.
                    </p>
                  </div>

                  <div>
                    <label
                      htmlFor="lab7-preset-select"
                      style={{
                        display: 'block',
                        fontSize: '12px',
                        fontWeight: 700,
                        color: 'var(--text-primary)',
                        marginBottom: '5px'
                      }}
                    >
                      Select Customer / Red-Team Payload Preset
                    </label>
                    <select
                      id="lab7-preset-select"
                      className="select-control"
                      value={selectedPresetId}
                      onChange={(e) => handleSelectPreset(e.target.value)}
                    >
                      {LAB7_SAMPLE_PRESETS.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.label}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {Object.entries(payloadDraft).map(([field, val]) => (
                      <div key={field}>
                        <label
                          htmlFor={`field-${field}`}
                          className="mono"
                          style={{
                            display: 'block',
                            fontSize: '11px',
                            color: 'var(--text-secondary)',
                            marginBottom: '3px'
                          }}
                        >
                          {field}
                        </label>
                        <input
                          id={`field-${field}`}
                          type="text"
                          className="input-control mono"
                          value={val}
                          onChange={(e) =>
                            setPayloadDraft((prev) => ({ ...prev, [field]: e.target.value }))
                          }
                        />
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '4px' }}>
                    <button
                      type="button"
                      className="btn btn-primary"
                      style={{ width: '100%' }}
                      disabled={isBusy}
                      onClick={() => void runEdgeDlpTokenize()}
                    >
                      <ShieldCheck size={14} />
                      <span>Submit KYC &amp; Payment to Edge DLP</span>
                      <ArrowRight size={14} />
                    </button>

                    <button
                      type="button"
                      className="btn btn-danger-soft"
                      style={{ width: '100%' }}
                      disabled={isBusy}
                      onClick={() => {
                        const attack = LAB7_SAMPLE_PRESETS.find((p) => p.attack_tag === '7A');
                        if (attack) {
                          setSelectedPresetId(attack.id);
                          setPayloadDraft({ ...attack.payload });
                          void runEdgeDlpTokenize({ ...attack.payload });
                        }
                      }}
                    >
                      <AlertTriangle size={14} />
                      <span>
                        Scenario 7A: Inject Raw api_key &amp; AKIA Secret → HTTP 403 BLOCK
                      </span>
                    </button>
                  </div>
                </div>

                {/* Right Column: Live 3-Gate Edge DLP + WebCrypto Envelope + Right-to-Erasure Trigger */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <div className={`gate-card ${getStage1GateState(1)}`}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ fontWeight: 700, fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {animatingGate === 1 ? <Loader2 size={15} className="spin" /> : <ShieldAlert size={15} />}
                          <span>Gate 1: Secret &amp; Credential Scanner (DLP-003)</span>
                        </div>
                        {getGateBadge(getStage1GateState(1))}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                        Fail-closed block on raw API keys, bearer tokens, or AWS AKIA credentials (HTTP 403).
                      </div>
                    </div>

                    <div className={`gate-card ${getStage1GateState(2)}`}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ fontWeight: 700, fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {animatingGate === 2 ? <Loader2 size={15} className="spin" /> : <ShieldCheck size={15} />}
                          <span>Gate 2: PII &amp; PCI Classifier (DLP-001, DLP-002, DLP-004)</span>
                        </div>
                        {getGateBadge(getStage1GateState(2))}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                        Detects PCI PANs, US SSNs, and Singapore NRIC / Malaysia MyKad identifiers.
                      </div>
                    </div>

                    <div className={`gate-card ${getStage1GateState(3)}`}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ fontWeight: 700, fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {animatingGate === 3 ? <Loader2 size={15} className="spin" /> : <FileLock2 size={15} />}
                          <span>Gate 3: Deterministic SHA-256 Edge Tokenizer</span>
                        </div>
                        {getGateBadge(getStage1GateState(3))}
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                        Replaces sensitive fields with deterministic <code className="mono">tok_&lt;type&gt;_&lt;sha256_8&gt;</code> pseudonyms.
                      </div>
                    </div>
                  </div>

                  {dlpResult && (
                    <div
                      className={`gate-card ${dlpResult.status === 'PASS' ? 'passed' : 'blocked'}`}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <strong style={{ fontSize: '13.5px' }}>
                          {dlpResult.status === 'PASS'
                            ? 'Edge DLP Passed — Raw PII/PCI Tokenized Before AI & Storage'
                            : 'Edge DLP Blocked — Raw Secret Leak Prevented (HTTP 403)'}
                        </strong>
                        <span className={`badge ${dlpResult.status === 'PASS' ? 'badge-emerald' : 'badge-crimson'}`}>
                          HTTP {dlpResult.http_status}
                        </span>
                      </div>
                      <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                        {dlpResult.status === 'PASS'
                          ? `${dlpResult.findings.length} sensitive fields tokenized at the edge. Raw values never reach AI models or storage.`
                          : dlpResult.blocked_reason}
                      </div>

                      {/* Raw vs Tokenized Edge Diff Table */}
                      {dlpResult.findings.length > 0 && (
                        <div className="data-table-wrapper" style={{ marginTop: '10px' }}>
                          <table className="data-table">
                            <thead>
                              <tr>
                                <th>Field</th>
                                <th>Rule / Class</th>
                                <th>Raw Input</th>
                                <th>Edge Output</th>
                              </tr>
                            </thead>
                            <tbody>
                              {dlpResult.findings.map((f, idx) => (
                                <tr key={`${f.rule_id}-${f.field_path}-${idx}`}>
                                  <td className="mono">{f.field_path}</td>
                                  <td>
                                    <span className="badge badge-slate">{f.rule_id}</span>{' '}
                                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                                      {f.classification}
                                    </span>
                                  </td>
                                  <td className="mono" style={{ color: 'var(--accent-crimson-ink)' }}>
                                    {f.original_preview}
                                  </td>
                                  <td className="mono" style={{ color: 'var(--accent-emerald-ink)' }}>
                                    {f.replacement}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}

                      {dlpResult.status === 'PASS' && (
                        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '12px' }}>
                          <button
                            type="button"
                            className="btn btn-dark btn-sm"
                            disabled={isBusy || isKekRevoked}
                            onClick={() => void runEnvelopeEncryption()}
                          >
                            <Lock size={13} />
                            <span>
                              {envelope
                                ? 'Re-Encrypt Record (WebCrypto Envelope)'
                                : 'Encrypt & Store Record (WebCrypto Envelope)'}
                            </span>
                          </button>

                          {envelope && (
                            <button
                              type="button"
                              className="btn btn-primary btn-sm"
                              onClick={() => setActiveSeat('ai-analyst')}
                            >
                              <span>Inspect as Data/AI Analyst (Devon Park)</span>
                              <ArrowRight size={13} />
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Stored WebCrypto Envelope + Right-to-Erasure Trigger Card */}
                  {envelope && (
                    <div
                      style={{
                        padding: '14px 16px',
                        borderRadius: 'var(--radius-md)',
                        border: '1px solid var(--accent-emerald-border)',
                        backgroundColor: 'var(--accent-emerald-dim)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '10px'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                        <div style={{ fontWeight: 700, fontSize: '13.5px', color: 'var(--accent-emerald-ink)' }}>
                          WebCrypto Envelope Stored in STATE_KV (1h TTL) · Plaintext Discarded
                        </div>
                        <span className="badge badge-emerald">{envelope.record_id}</span>
                      </div>

                      <div className="mono" style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                        <div>KEK: {envelope.key_id} (AES-KW-256 · extractable: false)</div>
                        <div>AAD: {envelope.aad_text}</div>
                        <div>IV (96-bit): {truncateMiddle(envelope.iv_b64, 16, 8)}</div>
                        <div>Wrapped DEK: {truncateMiddle(envelope.wrapped_dek_b64, 20, 12)}</div>
                        <div>Ciphertext: {truncateMiddle(envelope.ciphertext_b64, 22, 12)}</div>
                      </div>

                      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '4px' }}>
                        <button
                          type="button"
                          className="btn btn-danger-soft btn-sm"
                          disabled={erasureRequested || isKekRevoked}
                          onClick={handleRequestRightToErasure}
                        >
                          <Trash2 size={13} />
                          <span>
                            {erasureRequested
                              ? 'Erasure Request Queued for DPO'
                              : 'Request Right-to-Erasure (GDPR Art. 17 / PDPA)'}
                          </span>
                        </button>

                        {erasureRequested && (
                          <button
                            type="button"
                            className="btn btn-dark btn-sm"
                            onClick={() => setActiveSeat('dpo-kms')}
                          >
                            <span>Process Erasure as DPO (Elena Rostova)</span>
                            <ArrowRight size={13} />
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </section>
        )}

        {/* ==================== SEAT 2: DATA/AI ANALYST · BI/LLM WORKBENCH ==================== */}
        {activeSeat === 'ai-analyst' && (
          <section
            aria-label="Devon Park BI and LLM Risk Workbench"
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
              boxShadow: 'var(--shadow-sm)',
              overflow: 'hidden',
              marginBottom: '16px'
            }}
          >
            <div
              style={{
                padding: '12px 18px',
                borderBottom: '1px solid var(--border-subtle)',
                backgroundColor: 'var(--bg-canvas)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '10px',
                flexWrap: 'wrap'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <Sparkles size={16} color="#059669" />
                <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  BI &amp; LLM Risk Workbench · Tokenized-Only Analytics &amp; Cryptographic Verification
                </span>
              </div>

              <span className={`badge ${isKekRevoked ? 'badge-crimson' : 'badge-emerald'}`}>
                {isKekRevoked
                  ? `KEK REVOKED · ${tenantKey?.key_id}`
                  : `KEK ACTIVE · ${tenantKey?.key_id ?? 'kek-tenant-apac-01-v1'}`}
              </span>
            </div>

            <div style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {!envelope ? (
                <div
                  style={{
                    padding: '18px',
                    borderRadius: 'var(--radius-md)',
                    border: '1px dashed var(--border-strong)',
                    backgroundColor: 'var(--bg-canvas)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '10px'
                  }}
                >
                  <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    No Encrypted Customer Record in Warehouse Yet
                  </div>
                  <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                    Switch to <strong>Seat 1 (Mei-Ling Tan · Customer KYC)</strong> to tokenize and encrypt a customer record, or click below to auto-seed an encrypted envelope now.
                  </p>
                  <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      onClick={() => setActiveSeat('customer-kyc')}
                    >
                      <span>Switch to Seat 1 (Customer KYC)</span>
                      <ArrowRight size={13} />
                    </button>
                  </div>
                </div>
              ) : (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                    gap: '18px',
                    alignItems: 'start'
                  }}
                >
                  {/* Left Column: Stored Envelope & Analyst / Red-Team Controls */}
                  <div
                    style={{
                      padding: '16px',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--border-subtle)',
                      backgroundColor: 'var(--bg-canvas)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '12px'
                    }}
                  >
                    <div>
                      <div
                        style={{
                          fontSize: '11px',
                          fontWeight: 700,
                          textTransform: 'uppercase',
                          letterSpacing: '0.06em',
                          color: '#059669'
                        }}
                      >
                        Phase 2 · Understanding · Analyst &amp; LLM Boundary
                      </div>
                      <h2 style={{ fontSize: '15.5px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                        Stored Ciphertext Envelope ({envelope.record_id})
                      </h2>
                      <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                        Even with valid KMS unwrap permission, the BI/LLM Workbench only ever decrypts deterministic pseudonyms (<code>tok_nric_*</code>, <code>tok_ssn_*</code>, <code>tok_pan_*</code>). Once the DPO revokes the Tenant KEK, unwrap fails closed with <code>CRYPTO_SHREDDED_KEY_REVOKED</code>.
                      </p>
                    </div>

                    <div
                      className="mono"
                      style={{
                        padding: '10px 12px',
                        borderRadius: 'var(--radius-sm)',
                        backgroundColor: 'var(--bg-surface)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: '11.5px',
                        color: 'var(--text-secondary)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '4px'
                      }}
                    >
                      <div>Tenant: {envelope.tenant_id}</div>
                      <div>KEK Handle: {envelope.key_id} ({tenantKey?.status})</div>
                      <div>AAD Binding: {envelope.aad_text}</div>
                      <div>IV (96-bit): {truncateMiddle(envelope.iv_b64, 16, 10)}</div>
                      <div>Wrapped DEK: {truncateMiddle(envelope.wrapped_dek_b64, 18, 12)}</div>
                      <div>Ciphertext: {truncateMiddle(envelope.ciphertext_b64, 20, 12)}</div>
                    </div>

                    <button
                      type="button"
                      className="btn btn-primary"
                      style={{ width: '100%' }}
                      disabled={isBusy}
                      onClick={() => void runDecryptVerification('NORMAL')}
                    >
                      <KeyRound size={14} />
                      <span>Query Customer Record / Run AI Summary</span>
                    </button>

                    <hr style={{ border: 'none', borderTop: '1px solid var(--border-subtle)' }} />

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div style={{ fontSize: '12.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                        Red-Team &amp; Cryptographic Integrity Probes
                      </div>

                      <button
                        type="button"
                        className="btn btn-danger-soft"
                        disabled={isBusy}
                        onClick={() => void runDecryptVerification('POST_REVOKE_7B')}
                      >
                        <div style={{ textAlign: 'left' }}>
                          <div style={{ fontSize: '12.5px', fontWeight: 700 }}>
                            Scenario 7B: Post-Revocation Read Probe
                          </div>
                          <div style={{ fontSize: '11.5px', fontWeight: 400 }}>
                            {isKekRevoked
                              ? 'KEK is REVOKED → Verify HTTP 410 CRYPTO_SHREDDED_KEY_REVOKED'
                              : 'Auto-revokes Tenant KEK & verifies HTTP 410 CRYPTO_SHREDDED_KEY_REVOKED'}
                          </div>
                        </div>
                      </button>

                      <button
                        type="button"
                        className="btn btn-danger-soft"
                        disabled={isBusy}
                        onClick={() => void runDecryptVerification('CROSS_TENANT')}
                      >
                        <div style={{ textAlign: 'left' }}>
                          <div style={{ fontSize: '12.5px', fontWeight: 700 }}>
                            Scenario 7C: Cross-Tenant Key Mismatch
                          </div>
                          <div style={{ fontSize: '11.5px', fontWeight: 400 }}>
                            Unwrap {TENANT_ID} DEK with {FOREIGN_TENANT_ID} KEK → TENANT_KEY_MISMATCH
                          </div>
                        </div>
                      </button>

                      <button
                        type="button"
                        className="btn btn-danger-soft"
                        disabled={isBusy || isKekRevoked}
                        onClick={() => void runDecryptVerification('TAMPER')}
                      >
                        <div style={{ textAlign: 'left' }}>
                          <div style={{ fontSize: '12.5px', fontWeight: 700 }}>
                            Scenario 7D: Tamper Ciphertext / AAD Bit-Flip
                          </div>
                          <div style={{ fontSize: '11.5px', fontWeight: 400 }}>
                            Flip ciphertext bit before AES-GCM decrypt → INTEGRITY_CHECK_FAILED
                          </div>
                        </div>
                      </button>
                    </div>
                  </div>

                  {/* Right Column: 3 Decryption Verification Gates & LLM Context Output */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div className={`gate-card ${getStage3GateState(1)}`}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ fontWeight: 700, fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            {animatingGate === 1 ? <Loader2 size={15} className="spin" /> : <KeyRound size={15} />}
                            <span>Gate 1: Tenant KEK Lookup &amp; Revocation Check</span>
                          </div>
                          {getGateBadge(getStage3GateState(1))}
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                          Fails closed immediately with <code className="mono">CRYPTO_SHREDDED_KEY_REVOKED</code> if KEK is destroyed.
                        </div>
                      </div>

                      <div className={`gate-card ${getStage3GateState(2)}`}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ fontWeight: 700, fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            {animatingGate === 2 ? <Loader2 size={15} className="spin" /> : <Lock size={15} />}
                            <span>Gate 2: AES-KW DEK Unwrap (Per-Tenant Isolation)</span>
                          </div>
                          {getGateBadge(getStage3GateState(2))}
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                          Foreign tenant KEKs fail <code className="mono">crypto.subtle.unwrapKey</code> with <code className="mono">TENANT_KEY_MISMATCH</code>.
                        </div>
                      </div>

                      <div className={`gate-card ${getStage3GateState(3)}`}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div style={{ fontWeight: 700, fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                            {animatingGate === 3 ? <Loader2 size={15} className="spin" /> : <CheckCircle2 size={15} />}
                            <span>Gate 3: AES-GCM Authenticated Decryption &amp; AAD Check</span>
                          </div>
                          {getGateBadge(getStage3GateState(3))}
                        </div>
                        <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                          Verifies 128-bit GCM authentication tag and <code className="mono">{envelope.aad_text}</code> AAD binding.
                        </div>
                      </div>
                    </div>

                    {decryptResult && (
                      <div className={`gate-card ${decryptResult.ok ? 'passed' : 'blocked'}`}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <strong style={{ fontSize: '13.5px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            {decryptResult.ok ? (
                              <>
                                <CheckCircle2 size={16} />
                                <span>Decryption Succeeded — Tokenized Pseudonyms Only</span>
                              </>
                            ) : (
                              <>
                                <AlertTriangle size={16} />
                                <span>
                                  {decryptResult.status === 'CRYPTO_SHREDDED_KEY_REVOKED'
                                    ? 'HTTP 410 · CRYPTO-SHREDDED / PERMANENTLY UNREADABLE'
                                    : `HTTP 403 · ${decryptResult.status}`}
                                </span>
                              </>
                            )}
                          </strong>
                          <span className={`badge ${decryptResult.ok ? 'badge-emerald' : 'badge-crimson'}`}>
                            {decryptResult.error_code ?? 'HTTP 200 DECRYPTED'}
                          </span>
                        </div>

                        <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                          {decryptResult.ok
                            ? 'Active Tenant KEK unwrapped the DEK. Observe below that the Analyst and LLM prompt window only receive deterministic SHA-256 tokens — never raw NRIC, SSN, or PCI card numbers.'
                            : decryptResult.error_detail}
                        </div>

                        {decryptResult.ok && decryptResult.decrypted_payload && (
                          <pre
                            className="code-block"
                            style={{ marginTop: '10px', fontSize: '11.5px' }}
                          >
                            {JSON.stringify(decryptResult.decrypted_payload, null, 2)}
                          </pre>
                        )}

                        {decryptResult.ok && !isKekRevoked && (
                          <div style={{ marginTop: '10px' }}>
                            <button
                              type="button"
                              className="btn btn-dark btn-sm"
                              onClick={() => setActiveSeat('dpo-kms')}
                            >
                              <span>Switch to Seat 3 (DPO KMS Console) to Execute Crypto-Shredding</span>
                              <ArrowRight size={13} />
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* ==================== SEAT 3: DPO · KMS CONSOLE ==================== */}
        {activeSeat === 'dpo-kms' && (
          <section
            aria-label="Elena Rostova BYOK Key Management and Shredder Console"
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-lg)',
              boxShadow: 'var(--shadow-sm)',
              overflow: 'hidden',
              marginBottom: '16px'
            }}
          >
            <div
              style={{
                padding: '12px 18px',
                borderBottom: '1px solid var(--border-subtle)',
                backgroundColor: 'var(--bg-canvas)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '10px',
                flexWrap: 'wrap'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <Database size={16} color="#d97706" />
                <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  BYOK Key Management &amp; Shredder Console · DPO Governance
                </span>
              </div>

              <span className={`badge ${isKekRevoked ? 'badge-crimson' : erasureRequested ? 'badge-amber' : 'badge-emerald'}`}>
                {isKekRevoked
                  ? 'KEK REVOKED (CRYPTO-SHREDDED)'
                  : erasureRequested
                    ? '1 PENDING ERASURE REQUEST'
                    : 'ALL TENANT KEKS ACTIVE'}
              </span>
            </div>

            <div style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Multi-Tenant KMS Key Isolation Table */}
              <div>
                <div
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    color: '#d97706'
                  }}
                >
                  Phase 3 · Practice · Multi-Tenant Key Isolation vs. Blast-Radius Trap
                </div>
                <h2 style={{ fontSize: '15.5px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                  Tenant Key Hierarchy &amp; GDPR Art. 17 / PDPA Right-to-Erasure
                </h2>
                <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Compare compliant <strong>Per-Tenant BYOK KEK Revocation</strong> against the dangerous <strong>Shared Global KEK</strong> anti-pattern where revoking a master key to erase one customer causes collateral data loss across sibling tenants.
                </p>
              </div>

              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Tenant ID</th>
                      <th>Customer / Partition</th>
                      <th>Non-Extractable KEK ID</th>
                      <th>Wrapped Records</th>
                      <th>KMS Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {siblingTenants.map((tenant) => (
                      <tr key={tenant.tenant_id}>
                        <td className="mono" style={{ fontWeight: 700 }}>{tenant.tenant_id}</td>
                        <td>{tenant.region_label}</td>
                        <td className="mono">{tenant.key_id}</td>
                        <td className="mono">{tenant.records_count.toLocaleString()}</td>
                        <td>
                          <span
                            className={`badge ${
                              tenant.status === 'REVOKED' ? 'badge-crimson' : 'badge-emerald'
                            }`}
                          >
                            {tenant.status === 'REVOKED' ? 'REVOKED (SHREDDED)' : 'ACTIVE'}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Two-Column Decision Cards: Compliant Per-Tenant BYOK vs Shared-Key Trap */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                  gap: '16px'
                }}
              >
                {/* Option 1: Compliant Per-Tenant BYOK Crypto-Shredding */}
                <div
                  style={{
                    padding: '16px',
                    borderRadius: 'var(--radius-md)',
                    border: '1.5px solid var(--accent-emerald)',
                    backgroundColor: 'var(--bg-canvas)',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: '12px'
                  }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                      <span className="badge badge-emerald">Compliant Architecture · Per-Tenant BYOK</span>
                      <code className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        AES-KW-256
                      </code>
                    </div>
                    <div style={{ fontSize: '14.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                      Revoke Per-Tenant KEK (<code>{tenantKey?.key_id ?? 'kek-tenant-apac-01-v1'}</code>)
                    </div>
                    <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      Destroys only <code>{TENANT_ID}</code>&apos;s non-extractable KEK handle from memory and <code>STATE_KV</code>. Every wrapped DEK for <code>{TENANT_ID}</code> becomes permanently unwrappable while sibling tenants (<code>tenant-emea-99</code>, <code>tenant-amer-42</code>) remain 100% online.
                    </p>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <button
                      type="button"
                      className="btn btn-dark"
                      disabled={isBusy || isKekRevoked}
                      onClick={() => void handleRevokePerTenantKek()}
                    >
                      <Trash2 size={14} />
                      <span>
                        {isKekRevoked
                          ? 'Per-Tenant KEK Revoked (Crypto-Shredded)'
                          : `Revoke ${tenantKey?.key_id ?? 'kek-tenant-apac-01-v1'} (Crypto-Shred)`}
                      </span>
                    </button>

                    {isKekRevoked && (
                      <button
                        type="button"
                        className="btn btn-emerald btn-sm"
                        onClick={() => {
                          setActiveSeat('ai-analyst');
                          if (envelope) {
                            void runDecryptVerification('POST_REVOKE_7B');
                          }
                        }}
                      >
                        <span>Verify Post-Revocation Unreadability (7B) in Seat 2</span>
                        <ArrowRight size={13} />
                      </button>
                    )}
                  </div>
                </div>

                {/* Option 2: Safe-to-Fail Shared Multi-Tenant Master Key Trap */}
                <div
                  style={{
                    padding: '16px',
                    borderRadius: 'var(--radius-md)',
                    border: '1.5px solid var(--accent-crimson)',
                    backgroundColor: 'var(--bg-canvas)',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: '12px'
                  }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                      <span className="badge badge-crimson">Safe-to-Fail Trap · Shared Master KEK</span>
                      <code className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                        kek-global-shared-v1
                      </code>
                    </div>
                    <div style={{ fontSize: '14.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                      Revoke Shared Global KEK — Blast-Radius Trap
                    </div>
                    <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      Simulates the common anti-pattern of wrapping all tenants&apos; DEKs under one shared platform KEK. Attempting crypto-shredding on a shared key triggers a multi-tenant collateral blast-radius failure.
                    </p>
                  </div>

                  <button
                    type="button"
                    className="btn btn-danger-soft"
                    disabled={isBusy}
                    onClick={() => void handleTriggerSharedKeyTrap()}
                  >
                    <AlertOctagon size={14} />
                    <span>Revoke Shared Global KEK (Trigger Blast-Radius Trap)</span>
                  </button>
                </div>
              </div>

              {/* Shared Key Blast-Radius Failure Alert */}
              {sharedKeyTrapResult && (
                <div
                  role="alert"
                  style={{
                    padding: '14px 16px',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--accent-crimson-dim)',
                    border: '1.5px solid var(--accent-crimson)',
                    color: 'var(--accent-crimson-ink)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                    <strong style={{ fontSize: '13.5px', fontFamily: 'var(--font-mono)' }}>
                      HTTP {sharedKeyTrapResult.http_status} · {sharedKeyTrapResult.error_code}
                    </strong>
                    <span className="badge badge-crimson">
                      {sharedKeyTrapResult.collateral_records_at_risk.toLocaleString()} Sibling Records at Risk
                    </span>
                  </div>
                  <div style={{ fontSize: '12.5px' }}>{sharedKeyTrapResult.message}</div>
                  <div className="mono" style={{ fontSize: '11.5px' }}>
                    Collateral Tenants Impacted: {sharedKeyTrapResult.collateral_tenants_affected.join(', ')} · Invariant: {sharedKeyTrapResult.invariant}
                  </div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* ==================== PHASE 4: REFLECTION DEBRIEF ==================== */}
        {stage3Done && (
          <section
            aria-label="Phase 4 Reflection Debrief"
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1.5px solid var(--accent-emerald)',
              borderRadius: 'var(--radius-lg)',
              padding: '18px 20px',
              boxShadow: 'var(--shadow-sm)',
              display: 'flex',
              flexDirection: 'column',
              gap: '14px',
              marginBottom: '16px'
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '10px',
                flexWrap: 'wrap'
              }}
            >
              <div>
                <div
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    color: 'var(--accent-emerald)'
                  }}
                >
                  Phase 4 · Reflection Debrief
                </div>
                <h2 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Edge DLP Tokenization &amp; Per-Tenant BYOK Crypto-Shredding Proven
                </h2>
              </div>
              <button type="button" className="btn btn-sm" onClick={() => void handleReset()}>
                <RotateCcw size={12} />
                <span>Restart Lab</span>
              </button>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '10px'
              }}
            >
              <div
                style={{
                  padding: '12px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '12px'
                }}
              >
                <strong style={{ display: 'block', marginBottom: '4px', color: 'var(--text-primary)' }}>
                  1. Edge DLP Fail-Closed &amp; Tokenization
                </strong>
                <span style={{ color: 'var(--text-secondary)' }}>
                  <code>POST /api/data-byok/tokenize</code> blocks raw secrets (<code>DLP-003</code> → <code>HTTP 403</code>) and replaces NRIC, SSN, and PAN with SHA-256 tokens before AI or storage.
                </span>
              </div>

              <div
                style={{
                  padding: '12px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '12px'
                }}
              >
                <strong style={{ display: 'block', marginBottom: '4px', color: 'var(--text-primary)' }}>
                  2. Non-Extractable Envelope &amp; AAD
                </strong>
                <span style={{ color: 'var(--text-secondary)' }}>
                  Each record uses an ephemeral <code>AES-GCM-256</code> DEK bound to <code>tenant_id|record_id|key_version</code> AAD and wrapped by an <code>extractable: false</code> <code>AES-KW-256</code> KEK.
                </span>
              </div>

              <div
                style={{
                  padding: '12px',
                  borderRadius: 'var(--radius-sm)',
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '12px'
                }}
              >
                <strong style={{ display: 'block', marginBottom: '4px', color: 'var(--text-primary)' }}>
                  3. Per-Tenant BYOK vs. Shared-Key Blast Radius
                </strong>
                <span style={{ color: 'var(--text-secondary)' }}>
                  Per-tenant KEK revocation crypto-shreds <code>{TENANT_ID}</code> in milliseconds with zero collateral impact, avoiding the <code>HTTP 409</code> shared-key blast radius across sibling tenants.
                </span>
              </div>
            </div>

            <div
              style={{
                padding: '12px 14px',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-subtle)',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px'
              }}
            >
              <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)' }}>
                Security Traps &amp; Red-Team Scenarios Explored ({testedTrapCount} / {trapChecklist.length})
              </div>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
                  gap: '6px',
                  fontSize: '12px'
                }}
              >
                {trapChecklist.map((trap) => (
                  <div
                    key={trap.key}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '7px',
                      color: trap.tested ? 'var(--accent-emerald-ink)' : 'var(--text-muted)'
                    }}
                  >
                    <CheckCircle2
                      size={14}
                      color={trap.tested ? '#059669' : '#cbd5e1'}
                      style={{ flexShrink: 0 }}
                    />
                    <span>{trap.label}</span>
                  </div>
                ))}
              </div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)' }}>
                Open the sticky <strong>X-Ray Telemetry Drawer</strong> below to inspect every W3C{' '}
                <code>traceparent</code> span and decoded DLP, WebCrypto Envelope, and BYOK KMS proof payload.
              </div>
            </div>
          </section>
        )}
      </main>

      {/* Invariant 4: Sticky Bottom X-Ray Telemetry Drawer */}
      <XRayTelemetryDrawer
        spans={spans}
        decodedProofSections={decodedProofSections}
        onClear={() => setSpans([])}
      />
    </div>
  );
}
