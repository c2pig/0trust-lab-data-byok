import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateEdgeDlp,
  provisionTenantKek,
  encryptEnvelopeWithWebCrypto,
  decryptEnvelopeWithWebCrypto,
  revokeTenantKek,
  evaluateSharedKeyBlastRadiusTrap,
  getByokEngineStoreStats,
  getTokenVaultSnapshot,
  resetByokEngineStore,
  resetDataByokEngine
} from '../src/engine/dataByokEngine.ts';

const CORR_ID = 'corr-lab7-unit-test';
const TRACEPARENT = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

describe('Lab 7 Engine (src/engine/dataByokEngine.ts)', () => {
  beforeEach(() => {
    resetDataByokEngine();
  });

  it('evaluates Edge DLP: masks PII (SSN, credit card, email, MyKad) without false positives on clean payloads', async () => {
    const piiResult = await evaluateEdgeDlp(
      {
        email: 'alice@example.com',
        ssn: '123-45-6789',
        card: '4532-1234-5678-9012',
        mykad: '900101-14-5678'
      },
      CORR_ID,
      TRACEPARENT
    );
    assert.equal(piiResult.status, 'PASS');
    assert.ok(piiResult.findings.length >= 2);
    assert.notEqual(piiResult.sanitized_payload.ssn, '123-45-6789');
    assert.notEqual(piiResult.sanitized_payload.mykad, '900101-14-5678');

    const cleanResult = await evaluateEdgeDlp(
      {
        department: 'Engineering',
        region: 'APAC',
        tier: 'enterprise'
      },
      CORR_ID,
      TRACEPARENT
    );
    assert.equal(cleanResult.status, 'PASS');
    assert.equal(cleanResult.findings.length, 0);
    assert.deepEqual(cleanResult.sanitized_payload, {
      department: 'Engineering',
      region: 'APAC',
      tier: 'enterprise'
    });
  });

  it('blocks secrets (API keys and private keys) at Edge DLP', async () => {
    const awsKeyResult = await evaluateEdgeDlp(
      {
        aws_key: 'AKIAIOSFODNN7EXAMPLE'
      },
      CORR_ID,
      TRACEPARENT
    );
    assert.equal(awsKeyResult.status, 'BLOCK');
    assert.ok(awsKeyResult.findings.some((f) => f.action === 'BLOCK'));
  });

  it('performs WebCrypto envelope encryption round-trip and fails closed after revokeTenantKek', async () => {
    const tenantId = 'tenant-apac-01';
    const kekState = await provisionTenantKek(tenantId);
    const payload = { customer: 'Mei-Ling Tan', kyc_tier: 'platinum' };

    const envelope = await encryptEnvelopeWithWebCrypto(
      payload,
      [],
      kekState,
      CORR_ID,
      TRACEPARENT
    );
    assert.equal(envelope.tenant_id, tenantId);
    assert.ok(envelope.ciphertext_b64.length > 0);
    // Ciphertext must not contain plaintext
    assert.equal(
      Buffer.from(envelope.ciphertext_b64, 'base64').toString('utf8').includes('Mei-Ling Tan'),
      false
    );

    const decrypted = await decryptEnvelopeWithWebCrypto(
      envelope,
      kekState,
      CORR_ID,
      TRACEPARENT
    );
    assert.equal(decrypted.ok, true);
    assert.deepEqual(decrypted.decrypted_payload, payload);

    const revokedState = revokeTenantKek(kekState);
    assert.equal(revokedState.status, 'REVOKED');
    const failed = await decryptEnvelopeWithWebCrypto(
      envelope,
      revokedState,
      CORR_ID,
      TRACEPARENT
    );
    assert.equal(failed.ok, false);
    assert.equal(failed.decrypted_payload, undefined);
  });

  it('demonstrates shared-KEK blast radius vs tenant-isolated BYOK', () => {
    const trap = evaluateSharedKeyBlastRadiusTrap('tenant-apac-01', CORR_ID, TRACEPARENT);
    assert.equal(trap.status, 'SHARED_KEY_BLAST_RADIUS_BLOCKED');
    assert.equal(trap.http_status, 409);
    assert.equal(trap.error_code, 'SHARED_KEK_COLLATERAL_BLAST_RADIUS');
    assert.ok(trap.collateral_tenants_affected.length >= 2);
    assert.ok(trap.collateral_records_at_risk > 0);
  });

  it('clears tenantKekStore and tokenVault on resetByokEngineStore', async () => {
    const tenantId = 'tenant-apac-01';
    const kekState = await provisionTenantKek(tenantId);
    const dlp = await evaluateEdgeDlp(
      { email: 'alice@example.com', ssn: '123-45-6789' },
      CORR_ID,
      TRACEPARENT
    );
    const envelope = await encryptEnvelopeWithWebCrypto(
      dlp.sanitized_payload,
      dlp.findings,
      kekState,
      CORR_ID,
      TRACEPARENT
    );

    assert.ok(getTokenVaultSnapshot().length > 0);
    assert.deepEqual(getByokEngineStoreStats(), {
      kekCount: 1,
      tokenCount: getTokenVaultSnapshot().length
    });

    resetByokEngineStore();

    assert.deepEqual(getByokEngineStoreStats(), { kekCount: 0, tokenCount: 0 });
    assert.equal(getTokenVaultSnapshot().length, 0);

    const postResetDecrypt = await decryptEnvelopeWithWebCrypto(
      envelope,
      kekState,
      CORR_ID,
      TRACEPARENT
    );
    assert.equal(postResetDecrypt.ok, false);
    assert.equal(postResetDecrypt.error_code, 'CRYPTO_SHREDDED_KEY_REVOKED');
  });
});
