import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createCloudRunApp, verifyRouterSecret } from '../server/app';
import {
  buildKvDocId,
  FirestoreKvAdapter,
  MemoryKvAdapter,
  type FirestoreCollectionLike,
  type FirestoreKvDoc
} from '../server/kvAdapter';
import { resolvePublicOrigin } from '../server/origin';

const TEST_ROUTER_SECRET = 'test-router-secret-value-0123456789';

function createMockFirestoreCollection(): {
  collection: FirestoreCollectionLike;
  store: Map<string, FirestoreKvDoc>;
} {
  const store = new Map<string, FirestoreKvDoc>();
  const collection: FirestoreCollectionLike = {
    doc(id: string) {
      return {
        async get() {
          const data = store.get(id);
          return {
            exists: Boolean(data),
            data: () => data
          };
        },
        async set(data: FirestoreKvDoc) {
          store.set(id, data);
        },
        async delete() {
          store.delete(id);
        }
      };
    }
  };
  return { collection, store };
}

describe('Lab 7 (data-byok) Cloud Run Adapter — Security & API Invariants', () => {
  it('blocks direct *.run.app /api/* requests without or with invalid X-Lab-Router-Secret (fail-closed 403)', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'data-byok',
        LAB_ROUTER_SECRET: TEST_ROUTER_SECRET
      },
      kv: new MemoryKvAdapter({ labSlug: 'data-byok' })
    });

    // Missing header
    const resMissing = await app.request(
      'https://0trust-lab-data-byok-abc.run.app/api/data-byok/tokenize',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'tokenize', raw_payload: { note: 'hello' } })
      }
    );
    assert.equal(resMissing.status, 403);
    assert.deepEqual(await resMissing.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    // Wrong secret (same length & different length)
    const resWrongSameLen = await app.request(
      'https://0trust-lab-data-byok-abc.run.app/api/data-byok/tokenize',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': 'wrong-router-secret-value-987654321'
        },
        body: JSON.stringify({ action: 'tokenize', raw_payload: { note: 'hello' } })
      }
    );
    assert.equal(resWrongSameLen.status, 403);
    assert.deepEqual(await resWrongSameLen.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    const resWrongDiffLen = await app.request(
      'https://0trust-lab-data-byok-abc.run.app/api/data-byok/tokenize',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': 'short'
        },
        body: JSON.stringify({ action: 'tokenize', raw_payload: { note: 'hello' } })
      }
    );
    assert.equal(resWrongDiffLen.status, 403);

    // Fail-closed when LAB_ROUTER_SECRET is unset in production
    const appUnconfigured = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'data-byok'
      },
      kv: new MemoryKvAdapter({ labSlug: 'data-byok' })
    });
    const resUnconfigured = await appUnconfigured.request(
      'https://0trust-lab-data-byok-abc.run.app/api/data-byok/tokenize',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': TEST_ROUTER_SECRET
        },
        body: JSON.stringify({ action: 'tokenize', raw_payload: { note: 'hello' } })
      }
    );
    assert.equal(resUnconfigured.status, 403);
    assert.deepEqual(await resUnconfigured.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    // Valid secret succeeds
    const resValid = await app.request(
      'https://0trust-lab-data-byok-abc.run.app/api/data-byok/tokenize',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': TEST_ROUTER_SECRET
        },
        body: JSON.stringify({ action: 'tokenize', raw_payload: { note: 'hello' } })
      }
    );
    assert.equal(resValid.status, 200);
    const json = (await resValid.json()) as Record<string, unknown>;
    assert.equal(json.status, 'PASS');
    assert.equal(verifyRouterSecret(TEST_ROUTER_SECRET, TEST_ROUTER_SECRET), true);
  });

  it('serves GET /healthz without X-Lab-Router-Secret (Cloud Run probe)', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'data-byok',
        LAB_ROUTER_SECRET: TEST_ROUTER_SECRET
      },
      kv: new MemoryKvAdapter({ labSlug: 'data-byok' })
    });

    const res = await app.request('https://0trust-lab-data-byok-abc.run.app/healthz');
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, lab: 'data-byok' });
  });

  it('synchronously returns null on expired TTL docs in FirestoreKvAdapter & MemoryKvAdapter', async () => {
    let nowMs = 1_700_000_000_000;
    const { collection, store } = createMockFirestoreCollection();
    const firestoreKv = new FirestoreKvAdapter({
      labSlug: 'data-byok',
      collectionRef: collection,
      nowFn: () => nowMs
    });

    await firestoreKv.put('lab7:byok:session/1', '{"v":1}', { expirationTtl: 3600 });
    const expectedDocId = buildKvDocId('data-byok', 'lab7:byok:session/1');
    assert.equal(expectedDocId, 'data-byok:lab7%3Abyok%3Asession%2F1');

    const storedDoc = store.get(expectedDocId);
    assert.ok(storedDoc);
    assert.equal(storedDoc.labSlug, 'data-byok');
    assert.equal(storedDoc.value, '{"v":1}');
    assert.equal(storedDoc.expireAt?.toMillis(), nowMs + 3_600_000);

    // Before expiry
    assert.equal(await firestoreKv.get('lab7:byok:session/1'), '{"v":1}');

    // Advance clock past TTL without deleting the doc from Firestore (simulating delayed background reaper)
    nowMs += 3_600_000;
    assert.equal(store.has(expectedDocId), true);
    assert.equal(await firestoreKv.get('lab7:byok:session/1'), null);

    // MemoryKvAdapter parity
    let memNow = 1_700_000_000_000;
    const memKv = new MemoryKvAdapter({ labSlug: 'data-byok', nowFn: () => memNow });
    await memKv.put('lab7:byok:abc', 'ok', { expirationTtl: 10 });
    assert.equal(await memKv.get('lab7:byok:abc'), 'ok');
    memNow += 10_000;
    assert.equal(await memKv.get('lab7:byok:abc'), null);
  });

  it('rejects forged X-Forwarded-Host headers and allows lab.0trust.dev + localhost:5176', () => {
    const forgedReq = new Request(
      'https://0trust-lab-data-byok-abc.run.app/api/data-byok/tokenize',
      {
        headers: {
          'x-forwarded-host': 'evil.com',
          'x-forwarded-proto': 'https'
        }
      }
    );
    assert.equal(resolvePublicOrigin(forgedReq), 'https://0trust-lab-data-byok-abc.run.app');

    const prodReq = new Request('https://0trust-lab-data-byok-abc.run.app/api/data-byok/tokenize', {
      headers: {
        'x-forwarded-host': 'lab.0trust.dev',
        'x-forwarded-proto': 'https'
      }
    });
    assert.equal(resolvePublicOrigin(prodReq), 'https://lab.0trust.dev');

    const localReq = new Request('http://127.0.0.1:8080/api/data-byok/tokenize', {
      headers: {
        'x-forwarded-host': 'localhost:5176',
        'x-forwarded-proto': 'http'
      }
    });
    assert.equal(resolvePublicOrigin(localReq), 'http://localhost:5176');
  });

  it('redacts JWT signatures in _telemetry and never leaks X-Lab-Router-Secret or OTLP_AUTH_HEADER', async () => {
    const otlpAuthSecret = 'Bearer otlp-super-secret-header-token';
    const capturedOtlpBodies: string[] = [];
    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      capturedOtlpBodies.push(String(init?.body || ''));
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    try {
      const app = createCloudRunApp({
        env: {
          ENVIRONMENT: 'production',
          LAB_SLUG: 'data-byok',
          LAB_ROUTER_SECRET: TEST_ROUTER_SECRET,
          OTLP_ENDPOINT: 'https://otlp.example.com',
          OTLP_AUTH_HEADER: otlpAuthSecret
        },
        kv: new MemoryKvAdapter({ labSlug: 'data-byok' })
      });

      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkcG8tMSJ9.SuperSecretSignatureXYZ123';
      const res = await app.request(
        'https://0trust-lab-data-byok-abc.run.app/api/data-byok/tokenize',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-lab-router-secret': TEST_ROUTER_SECRET,
            authorization: `Bearer ${fakeJwt}`,
            traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
          },
          body: JSON.stringify({ action: 'tokenize', raw_payload: { note: 'clean record' } })
        }
      );

      assert.equal(res.status, 200);
      assert.ok(res.headers.get('traceparent')?.startsWith('00-4bf92f3577b34da6a3ce929d0e0e4736-'));
      assert.ok(res.headers.get('X-Edge-Latency-Ms'));

      const bodyText = await res.text();
      assert.ok(!bodyText.includes('SuperSecretSignatureXYZ123'), 'JWT signature must be redacted');
      assert.ok(!bodyText.includes(TEST_ROUTER_SECRET), 'Router secret must never appear in response');
      assert.ok(!bodyText.includes(otlpAuthSecret), 'OTLP auth header must never appear in response');

      const parsed = JSON.parse(bodyText) as {
        _telemetry: { redacted_auth_header: string; redaction_applied: boolean };
      };
      assert.equal(parsed._telemetry.redaction_applied, true);
      assert.equal(
        parsed._telemetry.redacted_auth_header,
        'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkcG8tMSJ9.***REDACTED***'
      );

      await new Promise((r) => setTimeout(r, 10));
      assert.equal(capturedOtlpBodies.length, 1);
      assert.ok(!capturedOtlpBodies[0].includes(TEST_ROUTER_SECRET));
      assert.ok(!capturedOtlpBodies[0].includes('SuperSecretSignatureXYZ123'));
      assert.ok(!capturedOtlpBodies[0].includes(otlpAuthSecret));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('executes full Lab 7 DLP Tokenize -> Secret Block -> Envelope Store -> Shared KEK Trap -> BYOK Revoke lifecycle', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'data-byok' });
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'development',
        LAB_SLUG: 'data-byok'
      },
      kv
    });

    const sessionId = 'test-byok-session';

    // 1. Tokenize PII payload -> 200 PASS with deterministic tokens
    const tokRes = await app.request('http://127.0.0.1:8080/api/data-byok/tokenize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        action: 'tokenize',
        tenant_id: 'tenant-apac-01',
        raw_payload: {
          ssn: '123-45-6789',
          customer_name: 'Mei-Ling Tan'
        }
      })
    });
    assert.equal(tokRes.status, 200);
    const tokData = (await tokRes.json()) as {
      status: string;
      sanitized_payload: Record<string, string>;
      findings: Array<{ rule_id: string }>;
    };
    assert.equal(tokData.status, 'PASS');
    assert.ok(tokData.findings.length >= 1);
    assert.ok(!tokData.sanitized_payload.ssn.includes('123-45-6789'));

    // 2. Fail-closed secret block (DLP-003) -> 403 DLP_SECRET_BLOCKED
    const blockRes = await app.request('http://127.0.0.1:8080/api/data-byok/tokenize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        action: 'tokenize',
        raw_payload: { aws_key: 'AKIAIOSFODNN7EXAMPLE' }
      })
    });
    assert.equal(blockRes.status, 403);
    const blockData = (await blockRes.json()) as { error_code: string };
    assert.equal(blockData.error_code, 'DLP_SECRET_BLOCKED');

    // 3. Store encrypted envelope -> 200 ENVELOPE_STORED
    const mockEnvelope = {
      record_id: 'rec-001',
      tenant_id: 'tenant-apac-01',
      key_id: 'kek-tenant-apac-01-v1',
      key_version: 1,
      algorithm: 'AES-GCM-256',
      iv_b64: 'AAAAAAAAAAA=',
      aad: 'tenant-apac-01|rec-001|1',
      ciphertext_b64: 'Y2lwaGVydGV4dA==',
      wrapped_dek_b64: 'd3JhcHBlZC1kZWs=',
      created_at: new Date().toISOString()
    };
    const storeRes = await app.request('http://127.0.0.1:8080/api/data-byok/tokenize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        action: 'store_envelope',
        tenant_id: 'tenant-apac-01',
        envelope: mockEnvelope
      })
    });
    assert.equal(storeRes.status, 200);
    const storeData = (await storeRes.json()) as { status: string };
    assert.equal(storeData.status, 'ENVELOPE_STORED');

    // 4. Shared Global KEK Trap -> 409 SHARED_KEK_COLLATERAL_BLAST_RADIUS
    const trapRes = await app.request('http://127.0.0.1:8080/api/data-byok/tokenize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        action: 'revoke_shared_kek_trap',
        tenant_id: 'tenant-apac-01'
      })
    });
    assert.equal(trapRes.status, 409);
    const trapData = (await trapRes.json()) as { error_code: string };
    assert.equal(trapData.error_code, 'SHARED_KEK_COLLATERAL_BLAST_RADIUS');

    // 5. Compliant per-tenant BYOK revocation -> 200 KEK_REVOKED
    const revokeRes = await app.request('http://127.0.0.1:8080/api/data-byok/tokenize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        action: 'revoke_kek',
        tenant_id: 'tenant-apac-01'
      })
    });
    assert.equal(revokeRes.status, 200);
    const revokeData = (await revokeRes.json()) as { status: string; sibling_tenants_impacted: number };
    assert.equal(revokeData.status, 'KEK_REVOKED');
    assert.equal(revokeData.sibling_tenants_impacted, 0);

    // 6. Post-revocation envelope store fails closed -> 403 CRYPTO_SHREDDED_KEY_REVOKED
    const postRevokeRes = await app.request('http://127.0.0.1:8080/api/data-byok/tokenize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        action: 'store_envelope',
        tenant_id: 'tenant-apac-01',
        envelope: mockEnvelope
      })
    });
    assert.equal(postRevokeRes.status, 403);
    const postRevokeData = (await postRevokeRes.json()) as { error_code: string };
    assert.equal(postRevokeData.error_code, 'CRYPTO_SHREDDED_KEY_REVOKED');
  });
});
