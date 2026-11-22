import {
  DataByokApiAction,
  DlpEvaluationResult,
  DlpFinding,
  DecryptVerificationResult,
  EncryptedEnvelopeRecord,
  LAB7_DLP_RULES,
  SharedKeyTrapResult,
  TenantKeyState
} from '../contracts/dataByokContract';
import { ObservabilitySpan } from '../types';

const tenantKekStore = new Map<string, CryptoKey>();
const tokenVault = new Map<string, { classification: string; masked_preview: string }>();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function kekMapKey(tenantId: string, keyVersion: number): string {
  return `${tenantId}:v${keyVersion}`;
}

export function createTraceContext(): { correlation_id: string; traceparent: string } {
  const traceBytes = crypto.getRandomValues(new Uint8Array(16));
  const spanBytes = crypto.getRandomValues(new Uint8Array(8));
  const traceId = toHex(traceBytes);
  const spanId = toHex(spanBytes);
  return {
    correlation_id: `corr-lab7-${traceId.slice(0, 12)}`,
    traceparent: `00-${traceId}-${spanId}-01`
  };
}

async function sha256Prefix8(value: string): Promise<string> {
  const encoded = new TextEncoder().encode(`0trust-lab7-salt:${value}`);
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(encoded));
  return toHex(new Uint8Array(digest)).slice(0, 8);
}

function maskPreview(raw: string): string {
  if (raw.length <= 6) return '***';
  return `${raw.slice(0, 3)}***${raw.slice(-3)}`;
}

/**
 * Deterministic Edge DLP classification & tokenization engine.
 * Evaluates DLP-003 (API_SECRET -> BLOCK) first, then DLP-001, DLP-002, DLP-004 (TOKENIZE).
 */
export async function evaluateEdgeDlp(
  rawPayload: Record<string, string>,
  correlationId: string,
  traceparent: string
): Promise<DlpEvaluationResult> {
  const findings: DlpFinding[] = [];
  const sanitizedPayload: Record<string, string> = {};
  let blockedReason: string | undefined;

  for (const [fieldPath, rawValue] of Object.entries(rawPayload)) {
    let currentValue = rawValue;

    for (const rule of LAB7_DLP_RULES) {
      const regex = new RegExp(rule.patternSource, rule.flags || 'g');
      const matches = Array.from(currentValue.matchAll(regex));

      if (matches.length === 0) continue;

      if (rule.action === 'BLOCK') {
        for (const m of matches) {
          const matchedText = m[0];
          findings.push({
            rule_id: rule.id,
            rule_name: rule.name,
            classification: rule.classification,
            action: 'BLOCK',
            field_path: fieldPath,
            original_preview: maskPreview(matchedText),
            replacement: '[BLOCKED_AT_EDGE_DLP]'
          });
        }
        blockedReason = `${rule.id} (${rule.name}) triggered on field "${fieldPath}": raw secret/credential material is never tokenized or forwarded.`;
        currentValue = '[BLOCKED_AT_EDGE_DLP]';
      } else {
        for (const m of matches) {
          const matchedText = m[0];
          const hash8 = await sha256Prefix8(`${rule.id}:${matchedText}`);
          const token = `${rule.tokenPrefix || 'tok_'}${hash8}`;
          tokenVault.set(token, {
            classification: rule.classification,
            masked_preview: maskPreview(matchedText)
          });
          currentValue = currentValue.replace(matchedText, token);
          findings.push({
            rule_id: rule.id,
            rule_name: rule.name,
            classification: rule.classification,
            action: rule.action,
            field_path: fieldPath,
            original_preview: maskPreview(matchedText),
            replacement: token
          });
        }
      }
    }

    sanitizedPayload[fieldPath] = currentValue;
  }

  const isBlocked = Boolean(blockedReason);

  return {
    correlation_id: correlationId,
    traceparent,
    status: isBlocked ? 'BLOCK' : 'PASS',
    http_status: isBlocked ? 403 : 200,
    findings,
    raw_payload: { ...rawPayload },
    sanitized_payload: sanitizedPayload,
    blocked_reason: blockedReason,
    evaluated_at: new Date().toISOString()
  };
}

/**
 * Generates a non-extractable AES-KW 256-bit Tenant Key Encryption Key (KEK)
 * using real browser crypto.subtle WebCrypto.
 */
export async function provisionTenantKek(
  tenantId: string,
  keyVersion = 1
): Promise<TenantKeyState> {
  const kek = await crypto.subtle.generateKey(
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );

  tenantKekStore.set(kekMapKey(tenantId, keyVersion), kek);

  return {
    tenant_id: tenantId,
    key_id: `kek-${tenantId}-v${keyVersion}`,
    key_version: keyVersion,
    algorithm: 'AES-KW',
    length: 256,
    extractable: false,
    status: 'ACTIVE',
    created_at: new Date().toISOString()
  };
}

/**
 * Encrypts a sanitized payload using real WebCrypto envelope encryption:
 * - Ephemeral AES-GCM 256-bit DEK
 * - 96-bit CSPRNG IV
 * - AAD bound to `${tenant_id}|${record_id}|${key_version}`
 * - DEK wrapped with non-extractable Tenant KEK via AES-KW
 */
export async function encryptEnvelopeWithWebCrypto(
  sanitizedPayload: Record<string, string>,
  dlpFindings: DlpFinding[],
  tenantKeyState: TenantKeyState,
  correlationId: string,
  traceparent: string
): Promise<EncryptedEnvelopeRecord> {
  if (tenantKeyState.status !== 'ACTIVE') {
    throw new Error('CRYPTO_SHREDDED_KEY_REVOKED: Active Tenant KEK required to encrypt.');
  }

  const kek = tenantKekStore.get(kekMapKey(tenantKeyState.tenant_id, tenantKeyState.key_version));
  if (!kek) {
    throw new Error('TENANT_KEK_NOT_FOUND: Tenant KEK is not present in memory.');
  }

  const recordSuffix = toHex(crypto.getRandomValues(new Uint8Array(4)));
  const recordId = `rec-${recordSuffix}`;
  const aadText = `${tenantKeyState.tenant_id}|${recordId}|${tenantKeyState.key_version}`;
  const aadBytes = new TextEncoder().encode(aadText);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(sanitizedPayload));

  const dek = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  const ciphertextBuf = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(aadBytes)
    },
    dek,
    toArrayBuffer(plaintextBytes)
  );

  const wrappedDekBuf = await crypto.subtle.wrapKey('raw', dek, kek, 'AES-KW');

  return {
    record_id: recordId,
    tenant_id: tenantKeyState.tenant_id,
    key_id: tenantKeyState.key_id,
    key_version: tenantKeyState.key_version,
    dek_algorithm: 'AES-GCM',
    dek_length: 256,
    kek_algorithm: 'AES-KW',
    iv_b64: toBase64(iv),
    wrapped_dek_b64: toBase64(new Uint8Array(wrappedDekBuf)),
    ciphertext_b64: toBase64(new Uint8Array(ciphertextBuf)),
    aad_b64: toBase64(aadBytes),
    aad_text: aadText,
    dlp_findings: dlpFindings,
    encrypted_at: new Date().toISOString(),
    correlation_id: correlationId,
    traceparent
  };
}

/**
 * Irreversible BYOK crypto-shredding: destroys the non-extractable Tenant KEK
 * from the in-memory keystore and marks the TenantKeyState as REVOKED.
 */
export function revokeTenantKek(tenantKeyState: TenantKeyState): TenantKeyState {
  tenantKekStore.delete(kekMapKey(tenantKeyState.tenant_id, tenantKeyState.key_version));
  return {
    ...tenantKeyState,
    status: 'REVOKED',
    revoked_at: new Date().toISOString()
  };
}

/**
 * Attempts to unwrap the DEK and decrypt the stored envelope using WebCrypto.
 * Supports negative test modes:
 * - Post-revocation read (Scenario 7B) -> CRYPTO_SHREDDED_KEY_REVOKED
 * - Cross-tenant key mismatch (Scenario 7C) -> TENANT_KEY_MISMATCH
 * - Ciphertext tamper -> INTEGRITY_CHECK_FAILED (AES-GCM OperationError)
 */
export async function decryptEnvelopeWithWebCrypto(
  envelope: EncryptedEnvelopeRecord,
  tenantKeyState: TenantKeyState,
  correlationId: string,
  traceparent: string,
  options?: {
    crossTenantId?: string;
    tamperCiphertext?: boolean;
  }
): Promise<DecryptVerificationResult> {
  const now = new Date().toISOString();

  // Scenario 7C: Cross-Tenant Key Mismatch (attempt unwrap with Tenant B's KEK)
  if (options?.crossTenantId) {
    const foreignKeyId = kekMapKey(options.crossTenantId, 1);
    let foreignKek = tenantKekStore.get(foreignKeyId);
    if (!foreignKek) {
      foreignKek = await crypto.subtle.generateKey(
        { name: 'AES-KW', length: 256 },
        false,
        ['wrapKey', 'unwrapKey']
      );
      tenantKekStore.set(foreignKeyId, foreignKek);
    }

    try {
      await crypto.subtle.unwrapKey(
        'raw',
        toArrayBuffer(fromBase64(envelope.wrapped_dek_b64)),
        foreignKek,
        'AES-KW',
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      return {
        ok: false,
        status: 'TENANT_KEY_MISMATCH',
        error_code: 'TENANT_KEY_MISMATCH',
        error_detail: `Cross-tenant unwrap unexpectedly succeeded.`,
        correlation_id: correlationId,
        traceparent,
        verified_at: now
      };
    } catch (err) {
      return {
        ok: false,
        status: 'TENANT_KEY_MISMATCH',
        error_code: 'TENANT_KEY_MISMATCH',
        error_detail: `WebCrypto AES-KW unwrapKey failed with foreign KEK (${options.crossTenantId}): ${err instanceof Error ? err.name : 'OperationError'}`,
        correlation_id: correlationId,
        traceparent,
        verified_at: now
      };
    }
  }

  // Scenario 7B: Post-Revocation Read -> Fail-closed immediately
  const activeKek = tenantKekStore.get(kekMapKey(envelope.tenant_id, envelope.key_version));
  if (tenantKeyState.status === 'REVOKED' || !activeKek) {
    return {
      ok: false,
      status: 'CRYPTO_SHREDDED_KEY_REVOKED',
      error_code: 'CRYPTO_SHREDDED_KEY_REVOKED',
      error_detail: `Tenant KEK ${envelope.key_id} has been permanently destroyed. Wrapped DEK cannot be unwrapped.`,
      correlation_id: correlationId,
      traceparent,
      verified_at: now
    };
  }

  try {
    const unwrappedDek = await crypto.subtle.unwrapKey(
      'raw',
      toArrayBuffer(fromBase64(envelope.wrapped_dek_b64)),
      activeKek,
      'AES-KW',
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );

    const ciphertextBytes = fromBase64(envelope.ciphertext_b64);
    if (options?.tamperCiphertext && ciphertextBytes.length > 0) {
      ciphertextBytes[0] = ciphertextBytes[0] ^ 0xff;
    }

    const decryptedBuf = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(fromBase64(envelope.iv_b64)),
        additionalData: toArrayBuffer(fromBase64(envelope.aad_b64))
      },
      unwrappedDek,
      toArrayBuffer(ciphertextBytes)
    );

    const decryptedText = new TextDecoder().decode(decryptedBuf);
    const decryptedPayload = JSON.parse(decryptedText) as Record<string, string>;

    return {
      ok: true,
      status: 'DECRYPTED',
      decrypted_payload: decryptedPayload,
      correlation_id: correlationId,
      traceparent,
      verified_at: now
    };
  } catch (err) {
    return {
      ok: false,
      status: 'INTEGRITY_CHECK_FAILED',
      error_code: 'INTEGRITY_CHECK_FAILED',
      error_detail: `WebCrypto AES-GCM authentication tag / AAD check failed (${err instanceof Error ? err.name : 'OperationError'}).`,
      correlation_id: correlationId,
      traceparent,
      verified_at: now
    };
  }
}

export function resetDataByokEngine(): void {
  tenantKekStore.clear();
  tokenVault.clear();
}

export function getTokenVaultSnapshot(): Array<{
  token: string;
  classification: string;
  masked_preview: string;
}> {
  return Array.from(tokenVault.entries()).map(([token, info]) => ({
    token,
    classification: info.classification,
    masked_preview: info.masked_preview
  }));
}

export function createDataByokSessionId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return `vis_byok_${toHex(bytes)}`;
}

export function evaluateSharedKeyBlastRadiusTrap(
  tenantId: string,
  correlationId: string,
  traceparent: string
): SharedKeyTrapResult {
  return {
    status: 'SHARED_KEY_BLAST_RADIUS_BLOCKED',
    http_status: 409,
    error_code: 'SHARED_KEK_COLLATERAL_BLAST_RADIUS',
    target_tenant: tenantId,
    collateral_tenants_affected: ['tenant-emea-99', 'tenant-amer-42'],
    collateral_records_at_risk: 14820,
    invariant: 'BYOK_PER_TENANT_KEK_ISOLATION',
    message:
      'Blast-Radius Trap Triggered: Revoking a Shared Global KEK to erase one customer destroys data for 2 innocent sibling tenants (tenant-emea-99, tenant-amer-42). Enforce per-tenant AES-KW-256 KEK isolation with tenant-bound AAD.',
    correlation_id: correlationId,
    traceparent,
    triggered_at: new Date().toISOString()
  };
}

export function createDataByokLocalSpan(options: {
  sessionId: string;
  method: string;
  path: string;
  status: number;
  latencyMs: number;
  traceparent: string;
  responseSummary: Record<string, unknown>;
}): ObservabilitySpan {
  const spanBytes = crypto.getRandomValues(new Uint8Array(5));
  const traceParts = options.traceparent.split('-');
  return {
    id: `span_${toHex(spanBytes)}`,
    traceparent: options.traceparent,
    trace_id: traceParts[1] || toHex(crypto.getRandomValues(new Uint8Array(16))),
    span_id: traceParts[2] || toHex(crypto.getRandomValues(new Uint8Array(8))),
    parent_span_id: '0000000000000000',
    session_id: options.sessionId,
    method: options.method,
    path: options.path,
    status: options.status,
    latency_ms: Math.max(1, options.latencyMs),
    timestamp: new Date().toISOString(),
    otlp_export: 'in-lab-only',
    redacted_auth_header: null,
    redaction_applied: false,
    execution_origin: 'browser-webcrypto-fallback',
    response_summary: options.responseSummary
  };
}

export interface DataByokApiCallResult<T = Record<string, unknown>> {
  ok: boolean;
  status: number;
  data: T;
  span: ObservabilitySpan;
}

let byokEdgeApiAvailable: boolean | null = null;

function sanitizeSummary(data: Record<string, unknown>): Record<string, unknown> {
  const clone: Record<string, unknown> = { ...data };
  delete clone._telemetry;
  return clone;
}

export async function callDataByokApi<T = Record<string, unknown>>(options: {
  sessionId: string;
  action: DataByokApiAction;
  tenantId?: string;
  correlationId?: string;
  traceparent?: string;
  rawPayload?: Record<string, string>;
  envelope?: EncryptedEnvelopeRecord;
}): Promise<DataByokApiCallResult<T>> {
  const path = '/api/data-byok/tokenize';
  const freshTrace = createTraceContext();
  const traceparent = options.traceparent || freshTrace.traceparent;
  const correlationId = options.correlationId || freshTrace.correlation_id;
  const tenantId = options.tenantId || 'tenant-apac-01';
  const start = performance.now();

  if (typeof window !== 'undefined' && byokEdgeApiAvailable === null) {
    try {
      const probe = await fetch('/api/state', { method: 'GET' });
      const probeCt = probe.headers.get('Content-Type') || '';
      byokEdgeApiAvailable = probeCt.includes('application/json');
    } catch {
      byokEdgeApiAvailable = false;
    }
  }

  if (!(typeof window !== 'undefined' && byokEdgeApiAvailable === false)) {
    try {
      const res = await fetch(path, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-Id': options.sessionId,
          traceparent
        },
        body: JSON.stringify({
          action: options.action,
          sessionId: options.sessionId,
          tenant_id: tenantId,
          correlation_id: correlationId,
          raw_payload: options.rawPayload,
          envelope: options.envelope
        })
      });

      const contentType = res.headers.get('Content-Type') || '';
      if (contentType.includes('application/json')) {
        if (typeof window !== 'undefined' && byokEdgeApiAvailable === null) {
          byokEdgeApiAvailable = true;
        }
        const json = (await res.json()) as Record<string, unknown>;
        const t = json._telemetry as Record<string, unknown> | undefined;
        const traceParts = traceparent.split('-');
        const span: ObservabilitySpan = {
          id: `span_${toHex(crypto.getRandomValues(new Uint8Array(5)))}`,
          traceparent: String(t?.traceparent || traceparent),
          trace_id: String(t?.trace_id || traceParts[1]),
          span_id: String(t?.span_id || traceParts[2]),
          parent_span_id: String(t?.parent_span_id || '0000000000000000'),
          session_id: String(t?.session_id || options.sessionId),
          method: 'POST',
          path: `${path} (${options.action})`,
          status: res.status,
          latency_ms: Number(t?.latency_ms || Math.max(1, Math.round(performance.now() - start))),
          timestamp: String(t?.timestamp || new Date().toISOString()),
          otlp_export: t?.otlp_export === 'configured' ? 'configured' : 'in-lab-only',
          redacted_auth_header: null,
          redaction_applied: false,
          execution_origin: 'cloudflare-edge',
          response_summary: sanitizeSummary(json)
        };
        return {
          ok: res.ok,
          status: res.status,
          data: json as T,
          span
        };
      }
      if (typeof window !== 'undefined' && byokEdgeApiAvailable === null) {
        byokEdgeApiAvailable = false;
      }
    } catch {
      if (typeof window !== 'undefined' && byokEdgeApiAvailable === null) {
        byokEdgeApiAvailable = false;
      }
    }
  }

  // Browser WebCrypto Fallback (for `vite dev`)
  let fbStatus = 200;
  let fbData: Record<string, unknown> = {};

  if (options.action === 'revoke_shared_kek_trap') {
    const trap = evaluateSharedKeyBlastRadiusTrap(tenantId, correlationId, traceparent);
    fbStatus = 409;
    fbData = { ...trap };
  } else if (options.action === 'revoke_kek') {
    fbStatus = 200;
    fbData = {
      status: 'KEK_REVOKED',
      http_status: 200,
      tenant_id: tenantId,
      key_id: `kek-${tenantId}-v1`,
      sibling_tenants_impacted: 0,
      sibling_tenants: [
        { tenant_id: 'tenant-emea-99', status: 'ACTIVE' },
        { tenant_id: 'tenant-amer-42', status: 'ACTIVE' }
      ],
      storage: 'browser-fallback',
      kv_ttl_seconds: 3600,
      correlation_id: correlationId,
      traceparent,
      revoked_at: new Date().toISOString()
    };
  } else if (options.action === 'store_envelope') {
    fbStatus = 200;
    fbData = {
      status: 'ENVELOPE_STORED',
      http_status: 200,
      record_id: options.envelope?.record_id || 'rec-unknown',
      tenant_id: options.envelope?.tenant_id || tenantId,
      key_id: options.envelope?.key_id || `kek-${tenantId}-v1`,
      envelope: options.envelope,
      storage: 'browser-fallback',
      kv_ttl_seconds: 3600,
      correlation_id: correlationId,
      traceparent,
      stored_at: new Date().toISOString()
    };
  } else {
    const dlp = await evaluateEdgeDlp(
      options.rawPayload || {},
      correlationId,
      traceparent
    );
    fbStatus = dlp.http_status;
    fbData = {
      ...dlp,
      error_code: dlp.status === 'BLOCK' ? 'DLP_SECRET_BLOCKED' : undefined,
      storage: 'browser-fallback',
      kv_ttl_seconds: 3600
    };
  }

  const span = createDataByokLocalSpan({
    sessionId: options.sessionId,
    method: 'POST',
    path: `${path} (${options.action})`,
    status: fbStatus,
    latencyMs: Math.round(performance.now() - start),
    traceparent,
    responseSummary: fbData
  });

  return {
    ok: fbStatus >= 200 && fbStatus < 300,
    status: fbStatus,
    data: fbData as unknown as T,
    span
  };
}
