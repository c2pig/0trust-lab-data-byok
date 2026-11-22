interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

function sanitizeSessionId(raw: string | null | undefined): string {
  if (!raw || typeof raw !== 'string') return 'demo-visitor';
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  return cleaned || 'demo-visitor';
}

import {
  LAB7_DLP_RULES,
  type DataByokApiAction,
  type DlpEvaluationResult,
  type DlpFinding,
  type EncryptedEnvelopeRecord,
  type SharedKeyTrapResult
} from '../../../src/contracts/dataByokContract';

export interface DataByokEnv {
  STATE_KV?: KVNamespace;
  ENVIRONMENT?: string;
}

interface StoredByokSessionRecord {
  session_id: string;
  tenant_id: string;
  kek_id: string;
  kek_status: 'ACTIVE' | 'REVOKED';
  dlp_result?: Omit<DlpEvaluationResult, 'raw_payload'>;
  envelope?: EncryptedEnvelopeRecord | null;
  revoked_at?: string;
  updated_at: string;
}

const BYOK_KV_TTL_SECONDS = 3600;
const MAX_PAYLOAD_BYTES = 64 * 1024;
const ephemeralByokStore = new Map<string, StoredByokSessionRecord>();

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
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

function resolveTraceparent(request: Request): string {
  const incoming = request.headers.get('traceparent');
  if (incoming && /^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/i.test(incoming.trim())) {
    return incoming.trim();
  }
  const traceBytes = crypto.getRandomValues(new Uint8Array(16));
  const spanBytes = crypto.getRandomValues(new Uint8Array(8));
  return `00-${toHex(traceBytes)}-${toHex(spanBytes)}-01`;
}

async function loadByokSession(
  env: DataByokEnv,
  sessionId: string
): Promise<StoredByokSessionRecord | null> {
  const kvKey = `lab7:byok:${sessionId}`;
  if (env.STATE_KV) {
    try {
      const raw = await env.STATE_KV.get(kvKey);
      if (raw) {
        return JSON.parse(raw) as StoredByokSessionRecord;
      }
    } catch {
      // Fall back to isolate-scoped Map
    }
  }
  return ephemeralByokStore.get(kvKey) || null;
}

async function saveByokSession(
  env: DataByokEnv,
  sessionId: string,
  record: StoredByokSessionRecord
): Promise<'cloudflare-kv' | 'ephemeral-edge'> {
  const kvKey = `lab7:byok:${sessionId}`;
  ephemeralByokStore.set(kvKey, record);
  if (env.STATE_KV) {
    try {
      await env.STATE_KV.put(kvKey, JSON.stringify(record), {
        expirationTtl: BYOK_KV_TTL_SECONDS
      });
      return 'cloudflare-kv';
    } catch {
      return 'ephemeral-edge';
    }
  }
  return 'ephemeral-edge';
}

export async function onRequestPost(context: {
  request: Request;
  env: DataByokEnv;
}): Promise<Response> {
  const rawText = await context.request.text();
  if (rawText.length > MAX_PAYLOAD_BYTES) {
    return jsonResponse(
      {
        status: 'PAYLOAD_TOO_LARGE',
        http_status: 413,
        error_code: 'PAYLOAD_TOO_LARGE',
        message: 'Payload exceeds 64KB Edge DLP limit.'
      },
      413
    );
  }

  let body: {
    action?: DataByokApiAction;
    sessionId?: string;
    tenant_id?: string;
    correlation_id?: string;
    raw_payload?: Record<string, string>;
    store_ciphertext?: boolean;
    envelope?: EncryptedEnvelopeRecord;
  } = {};

  if (rawText.trim()) {
    try {
      body = JSON.parse(rawText) as typeof body;
    } catch {
      return jsonResponse(
        {
          status: 'INVALID_JSON',
          http_status: 400,
          error_code: 'INVALID_JSON',
          message: 'Request body must be valid JSON.'
        },
        400
      );
    }
  }

  const sessionId = sanitizeSessionId(
    context.request.headers.get('X-Session-Id') || body.sessionId
  );
  const traceparent = resolveTraceparent(context.request);
  const traceParts = traceparent.split('-');
  const correlationId =
    typeof body.correlation_id === 'string' && body.correlation_id.trim()
      ? body.correlation_id.trim().slice(0, 64)
      : `corr-lab7-${(traceParts[1] || '000000000000').slice(0, 12)}`;
  const tenantId =
    typeof body.tenant_id === 'string' && body.tenant_id.trim()
      ? body.tenant_id.trim().slice(0, 64)
      : 'tenant-apac-01';
  const kekId = `kek-${tenantId}-v1`;
  const action: DataByokApiAction = body.action || 'tokenize';
  const nowIso = new Date().toISOString();

  // Action 4: Shared Global KEK Blast-Radius Trap -> HTTP 409
  if (action === 'revoke_shared_kek_trap') {
    const trapPayload: SharedKeyTrapResult = {
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
      triggered_at: nowIso
    };
    return jsonResponse(trapPayload, 409);
  }

  // Action 3: Compliant Per-Tenant BYOK KEK Revocation (Crypto-Shredding)
  if (action === 'revoke_kek') {
    const existing = await loadByokSession(context.env, sessionId);
    const updated: StoredByokSessionRecord = {
      session_id: sessionId,
      tenant_id: tenantId,
      kek_id: kekId,
      kek_status: 'REVOKED',
      dlp_result: existing?.dlp_result,
      envelope: existing?.envelope
        ? {
            ...existing.envelope,
            wrapped_dek_b64: '[CRYPTO_SHREDDED_KEK_DESTROYED]'
          }
        : null,
      revoked_at: nowIso,
      updated_at: nowIso
    };
    const storage = await saveByokSession(context.env, sessionId, updated);
    return jsonResponse(
      {
        status: 'KEK_REVOKED',
        http_status: 200,
        tenant_id: tenantId,
        key_id: kekId,
        sibling_tenants_impacted: 0,
        sibling_tenants: [
          { tenant_id: 'tenant-emea-99', status: 'ACTIVE' },
          { tenant_id: 'tenant-amer-42', status: 'ACTIVE' }
        ],
        storage,
        kv_ttl_seconds: BYOK_KV_TTL_SECONDS,
        correlation_id: correlationId,
        traceparent,
        revoked_at: nowIso
      },
      200
    );
  }

  // Action 2: Persist Encrypted WebCrypto Envelope to STATE_KV (1h TTL)
  if (action === 'store_envelope') {
    if (!body.envelope || typeof body.envelope !== 'object') {
      return jsonResponse(
        {
          status: 'MISSING_ENVELOPE',
          http_status: 400,
          error_code: 'MISSING_ENVELOPE',
          message: 'Encrypted envelope record is required for store_envelope.'
        },
        400
      );
    }

    const existing = await loadByokSession(context.env, sessionId);
    if (existing?.kek_status === 'REVOKED') {
      return jsonResponse(
        {
          status: 'CRYPTO_SHREDDED_KEY_REVOKED',
          http_status: 403,
          error_code: 'CRYPTO_SHREDDED_KEY_REVOKED',
          message: `Tenant KEK ${kekId} has been revoked. Active Tenant KEK required to persist envelope.`,
          correlation_id: correlationId,
          traceparent
        },
        403
      );
    }

    const updated: StoredByokSessionRecord = {
      session_id: sessionId,
      tenant_id: body.envelope.tenant_id || tenantId,
      kek_id: body.envelope.key_id || kekId,
      kek_status: 'ACTIVE',
      dlp_result: existing?.dlp_result,
      envelope: body.envelope,
      updated_at: nowIso
    };
    const storage = await saveByokSession(context.env, sessionId, updated);

    return jsonResponse(
      {
        status: 'ENVELOPE_STORED',
        http_status: 200,
        record_id: body.envelope.record_id,
        tenant_id: updated.tenant_id,
        key_id: updated.kek_id,
        envelope: body.envelope,
        storage,
        kv_ttl_seconds: BYOK_KV_TTL_SECONDS,
        correlation_id: correlationId,
        traceparent,
        stored_at: nowIso
      },
      200
    );
  }

  // Action 1 (default): Edge DLP Classification & Deterministic SHA-256 Tokenization
  const rawPayload =
    body.raw_payload && typeof body.raw_payload === 'object' ? body.raw_payload : {};
  const findings: DlpFinding[] = [];
  const sanitizedPayload: Record<string, string> = {};
  let blockedReason: string | undefined;

  for (const [fieldPath, rawVal] of Object.entries(rawPayload)) {
    let currentValue = typeof rawVal === 'string' ? rawVal : String(rawVal ?? '');

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

  if (blockedReason) {
    return jsonResponse(
      {
        status: 'BLOCK',
        http_status: 403,
        error_code: 'DLP_SECRET_BLOCKED',
        blocked_reason: blockedReason,
        findings,
        raw_payload: rawPayload,
        sanitized_payload: sanitizedPayload,
        correlation_id: correlationId,
        traceparent,
        evaluated_at: nowIso
      },
      403
    );
  }

  const recordToStore: StoredByokSessionRecord = {
    session_id: sessionId,
    tenant_id: tenantId,
    kek_id: kekId,
    kek_status: 'ACTIVE',
    dlp_result: {
      correlation_id: correlationId,
      traceparent,
      status: 'PASS',
      http_status: 200,
      findings,
      sanitized_payload: sanitizedPayload,
      evaluated_at: nowIso
    },
    envelope: body.envelope ?? null,
    updated_at: nowIso
  };

  const storage = await saveByokSession(context.env, sessionId, recordToStore);

  return jsonResponse(
    {
      status: 'PASS',
      http_status: 200,
      findings,
      raw_payload: rawPayload,
      sanitized_payload: sanitizedPayload,
      storage,
      kv_ttl_seconds: BYOK_KV_TTL_SECONDS,
      correlation_id: correlationId,
      traceparent,
      evaluated_at: nowIso
    },
    200
  );
}
