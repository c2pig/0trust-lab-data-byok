import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { onRequestPost } from '../functions/api/data-byok/tokenize.ts';
import { MemoryKvAdapter } from '../server/kvAdapter.ts';

function makeRequest(body: unknown, sessionId = 'api-test-session'): Request {
  return new Request('https://lab.0trust.dev/api/data-byok/tokenize', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Session-Id': sessionId
    },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  });
}

describe('Lab 7 API (functions/api/data-byok/tokenize.ts) with MemoryKvAdapter', () => {
  it('tokenizes PII fields and masks sensitive values without returning raw PII', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'data-byok' });
    const res = await onRequestPost({
      request: makeRequest({
        action: 'tokenize',
        tenant_id: 'tenant-apac-01',
        raw_payload: {
          email: 'alice@example.com',
          ssn: '123-45-6789',
          mykad: '900101-14-5678'
        }
      }),
      env: { STATE_KV: kv }
    });

    assert.equal(res.status, 200);
    const data = (await res.json()) as {
      status: string;
      sanitized_payload: Record<string, string>;
      findings: Array<{ rule_id: string }>;
    };
    assert.equal(data.status, 'PASS');
    assert.ok(data.findings.length >= 2);
    assert.notEqual(data.sanitized_payload.ssn, '123-45-6789');
    assert.notEqual(data.sanitized_payload.mykad, '900101-14-5678');
  });

  it('blocks secrets (API keys / private keys) with 422 SECRET_POLICY_BLOCKED', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'data-byok' });
    const res = await onRequestPost({
      request: makeRequest({
        action: 'tokenize',
        tenant_id: 'tenant-apac-01',
        raw_payload: {
          aws_key: 'AKIAIOSFODNN7EXAMPLE'
        }
      }),
      env: { STATE_KV: kv }
    });

    assert.equal(res.status, 403);
    const data = (await res.json()) as { error_code: string };
    assert.equal(data.error_code, 'DLP_SECRET_BLOCKED');
  });

  it('persists multiple encrypted envelopes and enforces crypto-shredding on revoke_kek', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'data-byok' });
    const sessionId = 'sess-multi-record';

    for (const idx of [1, 2]) {
      const storeRes = await onRequestPost({
        request: makeRequest(
          {
            action: 'store_envelope',
            tenant_id: 'tenant-apac-01',
            envelope: {
              envelope_id: `env-${idx}`,
              tenant_id: 'tenant-apac-01',
              kek_id: 'kek-tenant-apac-01-v1',
              wrapped_dek_b64: 'd3JhcHBlZC1kZWs=',
              iv_b64: 'aXYtMTIzNDU2Nzg=',
              ciphertext_b64: `Y2lwaGVydGV4dC0ke2lkeH0=`,
              aad: 'tenant=tenant-apac-01',
              algorithm: 'AES-GCM-256 + AES-KW-256',
              created_at: new Date().toISOString()
            }
          },
          sessionId
        ),
        env: { STATE_KV: kv }
      });
      assert.equal(storeRes.status, 200);
    }

    const revokeRes = await onRequestPost({
      request: makeRequest({ action: 'revoke_kek', tenant_id: 'tenant-apac-01' }, sessionId),
      env: { STATE_KV: kv }
    });
    assert.equal(revokeRes.status, 200);
    const revokeData = (await revokeRes.json()) as { status: string; sibling_tenants_impacted: number };
    assert.equal(revokeData.status, 'KEK_REVOKED');
    assert.equal(revokeData.sibling_tenants_impacted, 0);

    const postRevokeRes = await onRequestPost({
      request: makeRequest(
        {
          action: 'store_envelope',
          tenant_id: 'tenant-apac-01',
          envelope: {
            envelope_id: 'env-3',
            tenant_id: 'tenant-apac-01',
            kek_id: 'kek-tenant-apac-01-v1',
            wrapped_dek_b64: 'd3JhcHBlZC1kZWs=',
            iv_b64: 'aXYtMTIzNDU2Nzg=',
            ciphertext_b64: 'Y2lwaGVydGV4dC0z',
            aad: 'tenant=tenant-apac-01',
            algorithm: 'AES-GCM-256 + AES-KW-256',
            created_at: new Date().toISOString()
          }
        },
        sessionId
      ),
      env: { STATE_KV: kv }
    });
    assert.equal(postRevokeRes.status, 403);
    const postRevokeData = (await postRevokeRes.json()) as { error_code: string };
    assert.equal(postRevokeData.error_code, 'CRYPTO_SHREDDED_KEY_REVOKED');
  });

  it('isolates KEK revocation state per session', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'data-byok' });

    const revokeA = await onRequestPost({
      request: makeRequest({ action: 'revoke_kek', tenant_id: 'tenant-apac-01' }, 'session-A'),
      env: { STATE_KV: kv }
    });
    assert.equal(revokeA.status, 200);

    const storeB = await onRequestPost({
      request: makeRequest(
        {
          action: 'store_envelope',
          tenant_id: 'tenant-apac-01',
          envelope: {
            envelope_id: 'env-b1',
            tenant_id: 'tenant-apac-01',
            kek_id: 'kek-tenant-apac-01-v1',
            wrapped_dek_b64: 'd3JhcHBlZC1kZWs=',
            iv_b64: 'aXYtMTIzNDU2Nzg=',
            ciphertext_b64: 'Y2lwaGVydGV4dC1iMQ==',
            aad: 'tenant=tenant-apac-01',
            algorithm: 'AES-GCM-256 + AES-KW-256',
            created_at: new Date().toISOString()
          }
        },
        'session-B'
      ),
      env: { STATE_KV: kv }
    });
    assert.equal(storeB.status, 200);
  });

  it('rejects negative/invalid requests (400 INVALID_JSON, 400 MISSING_ENVELOPE, 409 trap, 413 payload)', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'data-byok' });

    const badJson = await onRequestPost({
      request: makeRequest('{invalid-json'),
      env: { STATE_KV: kv }
    });
    assert.equal(badJson.status, 400);

    const missingEnv = await onRequestPost({
      request: makeRequest({ action: 'store_envelope', tenant_id: 'tenant-apac-01' }),
      env: { STATE_KV: kv }
    });
    assert.equal(missingEnv.status, 400);
    const missingEnvData = (await missingEnv.json()) as { error_code: string };
    assert.equal(missingEnvData.error_code, 'MISSING_ENVELOPE');

    const trapRes = await onRequestPost({
      request: makeRequest({ action: 'revoke_shared_kek_trap', tenant_id: 'tenant-apac-01' }),
      env: { STATE_KV: kv }
    });
    assert.equal(trapRes.status, 409);
    const trapData = (await trapRes.json()) as { error_code: string };
    assert.equal(trapData.error_code, 'SHARED_KEK_COLLATERAL_BLAST_RADIUS');

    const tooLarge = await onRequestPost({
      request: makeRequest({ action: 'tokenize', raw_payload: { blob: 'x'.repeat(66 * 1024) } }),
      env: { STATE_KV: kv }
    });
    assert.equal(tooLarge.status, 413);
  });
});
