import React, { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowLeft, Compass, RotateCcw } from 'lucide-react';
import { driver } from 'driver.js';
import 'driver.js/dist/driver.css';
import {
  DataByokSeatId,
  DecryptVerificationResult,
  DlpEvaluationResult,
  EncryptedEnvelopeRecord,
  LAB7_SAMPLE_PRESETS,
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
    region_label: 'EMEA Treasury Partners',
    key_id: 'kek-tenant-emea-99-v1',
    records_count: 8410,
    status: 'ACTIVE'
  },
  {
    tenant_id: 'tenant-amer-42',
    region_label: 'AMER Institutional Clearing',
    key_id: 'kek-tenant-amer-42-v1',
    records_count: 6410,
    status: 'ACTIVE'
  }
];

export function DataByokPage({ onBack }: DataByokPageProps) {
  const [sessionId, setSessionId] = useState<string>(() => createDataByokSessionId());
  const sessionIdRef = useRef<string>(sessionId);
  sessionIdRef.current = sessionId;

  const [activeSeat, setActiveSeat] = useState<DataByokSeatId>('customer-kyc');
  const [payloadDraft, setPayloadDraft] = useState<Record<string, string>>({
    ...LAB7_SAMPLE_PRESETS[0].payload
  });
  const [traceCtx, setTraceCtx] = useState(() => createTraceContext());
  const [tenantKey, setTenantKey] = useState<TenantKeyState | null>(null);
  const [dlpResult, setDlpResult] = useState<DlpEvaluationResult | null>(null);
  const [envelope, setEnvelope] = useState<EncryptedEnvelopeRecord | null>(null);
  const [decryptResult, setDecryptResult] = useState<DecryptVerificationResult | null>(null);
  const [erasureRequested, setErasureRequested] = useState<boolean>(false);
  const [spans, setSpans] = useState<ObservabilitySpan[]>([]);
  const [isBusy, setIsBusy] = useState<boolean>(false);

  const tourLaunchedRef = useRef<boolean>(false);

  const recordSpan = useCallback((span: ObservabilitySpan) => {
    setSpans((prev) => [span, ...prev].slice(0, 40));
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
    };
  }, []);

  const startLabTour = useCallback(() => {
    const driverObj = driver({
      showProgress: true,
      animate: true,
      allowClose: true,
      overlayOpacity: 0.5,
      steps: [
        {
          popover: {
            title: 'Lab Orientation: Data Masking & BYOK Shredding',
            description:
              'Welcome to this interactive lab. You will submit sensitive KYC data, see how analytics only receives tokenized pseudonyms, and prove irreversible crypto-shredding via per-tenant key revocation.'
          }
        },
        {
          element: '#tour-role-switcher',
          popover: {
            title: 'Role Switcher',
            description:
              'Switch between Mei-Ling Tan (Customer), Devon Park (Data Analyst), and Elena Rostova (Data Protection Officer). Notification dots indicate pending erasure requests.'
          }
        },
        {
          element: '#tour-workspace',
          popover: {
            title: 'Role Workspace',
            description:
              'Start as Mei-Ling Tan in the Privacy & KYC Portal to submit and encrypt her profile, then submit a Data Erasure request.'
          }
        },
        {
          element: '.xray-drawer',
          popover: {
            title: 'X-Ray Telemetry Drawer',
            description:
              'Expand this bottom drawer anytime to inspect live HTTP spans, tokenized DLP outputs, and WebCrypto envelope proofs.'
          }
        },
        {
          element: '#tour-lab-controls',
          popover: {
            title: 'Lab Controls',
            description:
              'Use Lab Tour to replay this orientation, or Reset to provision a fresh tenant encryption key.'
          }
        }
      ]
    });
    driverObj.drive();
  }, []);

  useEffect(() => {
    if (tourLaunchedRef.current) return;
    tourLaunchedRef.current = true;
    const timer = window.setTimeout(() => {
      startLabTour();
    }, 300);
    return () => window.clearTimeout(timer);
  }, [startLabTour]);

  const handleReset = async () => {
    setIsBusy(false);
    resetDataByokEngine();

    const freshSid = createDataByokSessionId();
    sessionIdRef.current = freshSid;
    setSessionId(freshSid);

    const freshTrace = createTraceContext();
    const freshKek = await provisionTenantKek(TENANT_ID, 1);

    setActiveSeat('customer-kyc');
    setTraceCtx(freshTrace);
    setTenantKey(freshKek);
    setPayloadDraft({ ...LAB7_SAMPLE_PRESETS[0].payload });
    setDlpResult(null);
    setEnvelope(null);
    setDecryptResult(null);
    setErasureRequested(false);
    setSpans([]);
  };

  // Seat 1: Tokenize + Encrypt KYC Profile
  const handleSubmitKyc = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!tenantKey || tenantKey.status === 'REVOKED') return;
    const currentSid = sessionIdRef.current;
    setIsBusy(true);

    const apiRes = await callDataByokApi<DlpEvaluationResult>({
      sessionId: currentSid,
      action: 'tokenize',
      tenantId: TENANT_ID,
      correlationId: traceCtx.correlation_id,
      traceparent: traceCtx.traceparent,
      rawPayload: payloadDraft
    });

    if (sessionIdRef.current !== currentSid) return;
    recordSpan(apiRes.span);

    const result: DlpEvaluationResult = {
      correlation_id: apiRes.data.correlation_id || traceCtx.correlation_id,
      traceparent: apiRes.data.traceparent || traceCtx.traceparent,
      status: apiRes.data.status === 'BLOCK' ? 'BLOCK' : 'PASS',
      http_status: apiRes.status === 403 ? 403 : 200,
      findings: Array.isArray(apiRes.data.findings) ? apiRes.data.findings : [],
      raw_payload: apiRes.data.raw_payload || payloadDraft,
      sanitized_payload: apiRes.data.sanitized_payload || {},
      blocked_reason: apiRes.data.blocked_reason,
      evaluated_at: apiRes.data.evaluated_at || new Date().toISOString()
    };

    setDlpResult(result);
    setDecryptResult(null);

    if (result.status === 'PASS') {
      try {
        const record = await encryptEnvelopeWithWebCrypto(
          result.sanitized_payload,
          result.findings,
          tenantKey,
          traceCtx.correlation_id,
          traceCtx.traceparent
        );
        const storeRes = await callDataByokApi({
          sessionId: currentSid,
          action: 'store_envelope',
          tenantId: tenantKey.tenant_id,
          correlationId: traceCtx.correlation_id,
          traceparent: traceCtx.traceparent,
          envelope: record
        });
        if (sessionIdRef.current !== currentSid) return;
        recordSpan(storeRes.span);
        setEnvelope(record);
      } catch {
        setEnvelope(null);
      }
    }

    setIsBusy(false);
  };

  // Seat 1: Request Data Erasure
  const handleRequestErasure = () => {
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
        tenant_id: TENANT_ID,
        target_key_id: tenantKey?.key_id || 'kek-tenant-apac-01-v1'
      }
    });
    recordSpan(span);
  };

  // Seat 2: Analyst attempts authorized read
  const handleAnalystRead = async () => {
    if (!envelope || !tenantKey) return;
    const currentSid = sessionIdRef.current;
    setIsBusy(true);

    const res = await decryptEnvelopeWithWebCrypto(
      envelope,
      tenantKey,
      traceCtx.correlation_id,
      traceCtx.traceparent
    );

    if (sessionIdRef.current !== currentSid) return;
    setIsBusy(false);
    setDecryptResult(res);

    const span = createDataByokLocalSpan({
      sessionId: currentSid,
      method: 'POST',
      path: res.ok
        ? '/api/data-byok/decrypt-verify'
        : '/api/data-byok/decrypt-verify (revoked-kek)',
      status: res.ok ? 200 : 410,
      latencyMs: 5,
      traceparent: res.traceparent,
      responseSummary: {
        status: res.status,
        error_code: res.error_code
      }
    });
    recordSpan(span);
  };

  // Seat 3: DPO revokes per-tenant key
  const handleRevokeKey = async () => {
    if (!tenantKey || tenantKey.status === 'REVOKED') return;
    const currentSid = sessionIdRef.current;
    setIsBusy(true);

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
  };

  const isKeyRevoked = tenantKey?.status === 'REVOKED';

  const globalStatusLabel = isKeyRevoked
    ? 'Key Revoked (Shredded)'
    : erasureRequested
      ? 'Erasure Requested'
      : envelope
        ? 'Encrypted & Stored'
        : 'Ready';

  const seats: RoleSeatItem<DataByokSeatId>[] = [
    {
      id: 'customer-kyc',
      name: 'Mei-Ling Tan',
      roleLabel: 'Customer',
      appLabel: 'Privacy & KYC Portal',
      avatarInitials: 'MT',
      badge: erasureRequested ? { text: 'Erasure Sent', tone: 'amber' } : null
    },
    {
      id: 'ai-analyst',
      name: 'Devon Park',
      roleLabel: 'Data Analyst',
      appLabel: 'Analytics Workbench',
      avatarInitials: 'DP',
      badge: null
    },
    {
      id: 'dpo-kms',
      name: 'Elena Rostova',
      roleLabel: 'Data Protection Officer',
      appLabel: 'BYOK Key Management',
      avatarInitials: 'ER',
      badge:
        erasureRequested && !isKeyRevoked
          ? { text: '1 Request', tone: 'amber', pulse: true }
          : null
    }
  ];

  const decodedProofSections: XRayDecodedProofSection[] = [
    ...(dlpResult
      ? [
          {
            id: 'dlp-eval',
            label: 'Edge DLP & Tokenization',
            payload: dlpResult.sanitized_payload
          }
        ]
      : []),
    ...(envelope
      ? [
          {
            id: 'webcrypto-env',
            label: 'WebCrypto Envelope',
            payload: {
              record_id: envelope.record_id,
              tenant_id: envelope.tenant_id,
              key_id: envelope.key_id,
              dek_algorithm: envelope.dek_algorithm,
              kek_algorithm: envelope.kek_algorithm,
              aad_text: envelope.aad_text
            }
          }
        ]
      : []),
    ...(tenantKey
      ? [
          {
            id: 'tenant-kek',
            label: 'Tenant KEK Status',
            payload: {
              key_id: tenantKey.key_id,
              status: tenantKey.status,
              extractable: tenantKey.extractable,
              revoked_at: tenantKey.revoked_at || null
            }
          }
        ]
      : [])
  ];

  const fieldEntries = Object.entries(payloadDraft);
  const sanitizedEntries = dlpResult ? Object.entries(dlpResult.sanitized_payload) : [];

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: 'var(--bg-canvas)',
        color: 'var(--text-primary)'
      }}
    >
      {/* 1. Compact AppShell Top Header */}
      <header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 40,
          backgroundColor: 'rgba(255, 255, 255, 0.96)',
          backdropFilter: 'blur(8px)',
          borderBottom: '1px solid var(--border-subtle)'
        }}
      >
        <div
          style={{
            maxWidth: '1280px',
            margin: '0 auto',
            padding: '0 16px',
            height: '56px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
            <button
              type="button"
              onClick={onBack}
              className="btn btn-sm"
              style={{ padding: '5px 9px' }}
              title="All Labs"
            >
              <ArrowLeft size={13} />
              <span>All Labs</span>
            </button>
            <span
              style={{
                fontSize: '14px',
                fontWeight: 700,
                color: 'var(--text-primary)',
                whiteSpace: 'nowrap'
              }}
            >
              Data Masking &amp; BYOK Crypto-Shredding
            </span>
            <span className="badge" style={{ whiteSpace: 'nowrap', fontSize: '12px' }}>
              {globalStatusLabel}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            <RoleSwitcherBar
              seats={seats}
              activeSeatId={activeSeat}
              onSelectSeat={setActiveSeat}
              ariaLabel="Switch workspace persona"
            />

            <div id="tour-lab-controls" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                type="button"
                onClick={startLabTour}
                className="btn btn-sm"
                style={{
                  backgroundColor: 'var(--accent-primary-dim)',
                  borderColor: 'var(--accent-primary-border)',
                  color: 'var(--accent-primary-ink)',
                  fontSize: '13px'
                }}
              >
                <Compass size={14} />
                <span>Lab Tour</span>
              </button>
              <button
                type="button"
                onClick={() => void handleReset()}
                className="btn btn-sm"
                style={{ fontSize: '13px' }}
              >
                <RotateCcw size={14} />
                <span>Reset</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* 2. Center Role Workspace */}
      <main id="tour-workspace" style={{ flex: 1, padding: '16px' }}>
        <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {/* ==================== SEAT 1: MEI-LING TAN — PRIVACY & KYC PORTAL ==================== */}
          {activeSeat === 'customer-kyc' && (
            <section
              aria-label="FinCore Privacy and KYC Portal"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: '#0f172a',
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#2563eb',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    FC
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>
                    FinCore Privacy &amp; KYC Portal
                  </span>
                </div>
                <span style={{ fontSize: '13px', color: '#e2e8f0' }}>
                  Mei-Ling Tan · Customer
                </span>
              </div>

              <form onSubmit={(e) => void handleSubmitKyc(e)} style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <h2 style={{ fontSize: '15.5px', fontWeight: 700 }}>Customer Onboarding Profile</h2>
                  <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                    Sensitive identity and card fields are tokenized at the edge and encrypted with your tenant key.
                  </p>
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                    gap: '12px'
                  }}
                >
                  {fieldEntries.map(([key, val]) => (
                    <div key={key}>
                      <label
                        style={{
                          display: 'block',
                          fontSize: '12.5px',
                          fontWeight: 600,
                          color: 'var(--text-secondary)',
                          marginBottom: '4px',
                          textTransform: 'capitalize'
                        }}
                      >
                        {key.replace(/_/g, ' ')}
                      </label>
                      <input
                        type="text"
                        value={val}
                        onChange={(e) =>
                          setPayloadDraft((prev) => ({ ...prev, [key]: e.target.value }))
                        }
                        className="input-control"
                        style={{ fontSize: '13.5px' }}
                        disabled={isKeyRevoked}
                      />
                    </div>
                  ))}
                </div>

                {envelope && !isKeyRevoked && (
                  <div
                    style={{
                      padding: '12px 14px',
                      borderRadius: '8px',
                      backgroundColor: 'var(--accent-emerald-dim)',
                      border: '1px solid var(--accent-emerald-border)',
                      color: 'var(--accent-emerald-ink)',
                      fontSize: '13.5px'
                    }}
                  >
                    <strong>Profile Encrypted &amp; Stored:</strong> {dlpResult?.findings.length || 0} sensitive fields
                    tokenized into record <code className="mono">{envelope.record_id}</code>.
                  </div>
                )}

                {erasureRequested && !isKeyRevoked && (
                  <div
                    style={{
                      padding: '12px 14px',
                      borderRadius: '8px',
                      backgroundColor: 'var(--accent-amber-dim)',
                      border: '1px solid var(--accent-amber-border)',
                      color: 'var(--accent-amber-ink)',
                      fontSize: '13.5px'
                    }}
                  >
                    <strong>Erasure Request Submitted:</strong> Queued for review by the Data Protection Officer.
                  </div>
                )}

                {isKeyRevoked && (
                  <div
                    style={{
                      padding: '12px 14px',
                      borderRadius: '8px',
                      backgroundColor: 'var(--accent-crimson-dim)',
                      border: '1px solid var(--accent-crimson-border)',
                      color: 'var(--accent-crimson-ink)',
                      fontSize: '13.5px'
                    }}
                  >
                    <strong>Data Permanently Shredded:</strong> Your tenant encryption key has been revoked. Stored records are unreadable.
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', flexWrap: 'wrap' }}>
                  {envelope && !isKeyRevoked && (
                    <button
                      type="button"
                      className="btn btn-amber-soft"
                      style={{ fontSize: '13.5px', padding: '9px 14px' }}
                      disabled={erasureRequested}
                      onClick={handleRequestErasure}
                    >
                      {erasureRequested ? 'Erasure Requested' : 'Request Data Erasure (GDPR / PDPA)'}
                    </button>
                  )}
                  <button
                    type="submit"
                    className="btn btn-primary"
                    style={{ fontSize: '13.5px', padding: '9px 16px' }}
                    disabled={isBusy || isKeyRevoked}
                  >
                    {isBusy ? 'Tokenizing & Encrypting…' : 'Submit & Encrypt KYC Profile'}
                  </button>
                </div>
              </form>
            </section>
          )}

          {/* ==================== SEAT 2: DEVON PARK — ANALYTICS WORKBENCH ==================== */}
          {activeSeat === 'ai-analyst' && (
            <section
              aria-label="Analytics Workbench"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: 'var(--bg-canvas)',
                  borderBottom: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#059669',
                      color: '#ffffff',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    BI
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>Analytics Workbench</span>
                </div>
                <span style={{ fontSize: '13.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                  Devon Park · Data Analyst
                </span>
              </div>

              <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
                  <div>
                    <h2 style={{ fontSize: '15.5px', fontWeight: 700 }}>Tokenized Customer Dataset</h2>
                    <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                      Analytics queries only see masked pseudonyms; authorized decryption requires an active tenant key.
                    </p>
                  </div>
                  {envelope && (
                    <button
                      type="button"
                      className="btn btn-primary"
                      style={{ fontSize: '13.5px', padding: '9px 16px' }}
                      disabled={isBusy}
                      onClick={() => void handleAnalystRead()}
                    >
                      {isBusy ? 'Verifying Key…' : 'Run Authorized Read'}
                    </button>
                  )}
                </div>

                {!envelope ? (
                  <div
                    style={{
                      border: '1px dashed var(--border-strong)',
                      borderRadius: 'var(--radius-md)',
                      padding: '28px 16px',
                      textAlign: 'center',
                      backgroundColor: 'var(--bg-canvas)',
                      fontSize: '13.5px',
                      color: 'var(--text-secondary)'
                    }}
                  >
                    No customer records stored yet.
                  </div>
                ) : (
                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Field</th>
                          <th>Masked Value (Analytics View)</th>
                          <th>Encryption Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sanitizedEntries.map(([field, maskedVal]) => (
                          <tr key={field}>
                            <td style={{ fontWeight: 600, textTransform: 'capitalize' }}>
                              {field.replace(/_/g, ' ')}
                            </td>
                            <td className="mono">{maskedVal}</td>
                            <td>
                              {isKeyRevoked ? (
                                <span className="badge badge-crimson">KEY REVOKED</span>
                              ) : (
                                <span className="badge badge-emerald">ENCRYPTED</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {decryptResult && (
                  <div
                    style={{
                      padding: '12px 14px',
                      borderRadius: '8px',
                      backgroundColor: decryptResult.ok
                        ? 'var(--accent-emerald-dim)'
                        : 'var(--accent-crimson-dim)',
                      border: `1px solid ${
                        decryptResult.ok
                          ? 'var(--accent-emerald-border)'
                          : 'var(--accent-crimson-border)'
                      }`,
                      color: decryptResult.ok
                        ? 'var(--accent-emerald-ink)'
                        : 'var(--accent-crimson-ink)',
                      fontSize: '13.5px'
                    }}
                  >
                    {decryptResult.ok ? (
                      <>
                        <strong>Authorized Read Succeeded (HTTP 200):</strong> Envelope unwrapped with active tenant key{' '}
                        <code className="mono">{tenantKey?.key_id}</code>.
                      </>
                    ) : (
                      <>
                        <strong>Access Denied — Key Revoked (HTTP 410):</strong>{' '}
                        {decryptResult.error_detail || 'Tenant encryption key was destroyed; data is permanently unreadable.'}
                      </>
                    )}
                  </div>
                )}
              </div>
            </section>
          )}

          {/* ==================== SEAT 3: ELENA ROSTOVA — BYOK KEY MANAGEMENT ==================== */}
          {activeSeat === 'dpo-kms' && (
            <section
              aria-label="BYOK Key Management Console"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: 'var(--bg-canvas)',
                  borderBottom: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#7c3aed',
                      color: '#ffffff',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    KM
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>
                    BYOK Key Management Console
                  </span>
                </div>
                <span style={{ fontSize: '13.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                  Elena Rostova · Data Protection Officer
                </span>
              </div>

              {erasureRequested && !isKeyRevoked && (
                <div
                  style={{
                    padding: '10px 18px',
                    backgroundColor: 'var(--accent-amber-dim)',
                    borderBottom: '1px solid var(--accent-amber-border)',
                    color: 'var(--accent-amber-ink)',
                    fontSize: '13.5px'
                  }}
                >
                  <strong>Erasure Request Pending:</strong> Mei-Ling Tan (APAC Financial Holdings) requested immediate GDPR/PDPA data erasure.
                </div>
              )}

              <div style={{ padding: '18px' }}>
                <div className="data-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Tenant</th>
                        <th>Key ID</th>
                        <th>Records</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {INITIAL_SIBLING_TENANTS.map((row) => {
                        const isTarget = row.tenant_id === TENANT_ID;
                        const rowRevoked = isTarget && isKeyRevoked;
                        return (
                          <tr key={row.tenant_id}>
                            <td>
                              <div style={{ fontWeight: 700 }}>{row.region_label}</div>
                              <div className="mono" style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                                {row.tenant_id}
                              </div>
                            </td>
                            <td className="mono">{row.key_id}</td>
                            <td className="mono">{row.records_count.toLocaleString()}</td>
                            <td>
                              {rowRevoked ? (
                                <span className="badge badge-crimson">REVOKED</span>
                              ) : (
                                <span className="badge badge-emerald">ACTIVE</span>
                              )}
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              {isTarget ? (
                                <button
                                  type="button"
                                  className="btn btn-sm"
                                  disabled={isBusy || rowRevoked}
                                  onClick={() => void handleRevokeKey()}
                                  style={{
                                    fontSize: '13px',
                                    padding: '6px 12px',
                                    backgroundColor: rowRevoked ? 'var(--bg-elevated)' : 'var(--accent-crimson)',
                                    borderColor: rowRevoked ? 'var(--border-strong)' : 'var(--accent-crimson)',
                                    color: rowRevoked ? 'var(--text-muted)' : '#ffffff'
                                  }}
                                >
                                  {rowRevoked ? 'Shredded' : 'Revoke & Shred Key'}
                                </button>
                              ) : (
                                <span style={{ color: 'var(--text-muted)', fontSize: '12.5px' }}>
                                  Isolated
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          )}
        </div>
      </main>

      {/* 3. Original Sticky-Bottom X-Ray Telemetry Drawer */}
      <XRayTelemetryDrawer
        spans={spans}
        decodedProofSections={decodedProofSections}
        onClear={() => setSpans([])}
      />
    </div>
  );
}
