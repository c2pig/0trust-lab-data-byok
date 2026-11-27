import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDataByokSeatBadges,
  getDataByokActionGates,
  getEnvelopeStatusBadge,
  getTenantKekBadge
} from '../src/engine/dataByokSelectors.ts';

describe('Lab 7 UI Selectors (src/engine/dataByokSelectors.ts)', () => {
  it('derives seat badges for initial, erasure-requested, and key-revoked states', () => {
    const initial = buildDataByokSeatBadges(false, false);
    assert.equal(initial['customer-kyc'], null);
    assert.equal(initial['ai-analyst'], null);
    assert.equal(initial['dpo-kms'], null);

    const requested = buildDataByokSeatBadges(true, false);
    assert.deepEqual(requested['customer-kyc'], { text: 'Erasure Sent', tone: 'amber' });
    assert.deepEqual(requested['dpo-kms'], { text: '1 Request', tone: 'amber', pulse: true });

    const revoked = buildDataByokSeatBadges(true, true);
    assert.deepEqual(revoked['customer-kyc'], { text: 'Erasure Sent', tone: 'amber' });
    assert.equal(revoked['dpo-kms'], null);
  });

  it('computes action gates based on busy, key-revoked, and erasure-requested flags', () => {
    const ready = getDataByokActionGates({
      isBusy: false,
      isKeyRevoked: false,
      erasureRequested: false
    });
    assert.equal(ready.canEncryptEnvelope, true);
    assert.equal(ready.canRequestErasure, true);
    assert.equal(ready.canRevokeKek, true);

    const revoked = getDataByokActionGates({
      isBusy: false,
      isKeyRevoked: true,
      erasureRequested: true
    });
    assert.equal(revoked.canEncryptEnvelope, false);
    assert.equal(revoked.canRequestErasure, false);
    assert.equal(revoked.canRevokeKek, false);
  });

  it('derives envelope and tenant KEK status badges', () => {
    assert.deepEqual(getEnvelopeStatusBadge(false), { label: 'ENCRYPTED', tone: 'emerald' });
    assert.deepEqual(getEnvelopeStatusBadge(true), { label: 'KEY REVOKED', tone: 'crimson' });
    assert.deepEqual(getTenantKekBadge(false), { label: 'ACTIVE', tone: 'emerald' });
    assert.deepEqual(getTenantKekBadge(true), { label: 'REVOKED', tone: 'crimson' });
  });
});
