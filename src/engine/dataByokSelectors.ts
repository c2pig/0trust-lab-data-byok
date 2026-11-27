/**
 * Pure, DOM-free UI selectors for Lab 7 (Data Classification, Masking & BYOK Crypto-Shredding).
 */

export type DataByokSeatId = 'customer-kyc' | 'ai-analyst' | 'dpo-kms';

export interface SeatBadgeDescriptor {
  text: string;
  tone: 'amber' | 'emerald' | 'crimson';
  pulse?: boolean;
}

export interface DataByokActionGates {
  canEncryptEnvelope: boolean;
  canRequestErasure: boolean;
  canRevokeKek: boolean;
}

export interface StatusBadgeDescriptor {
  label: string;
  tone: 'crimson' | 'emerald';
}

export function buildDataByokSeatBadges(
  erasureRequested: boolean,
  isKeyRevoked: boolean
): Record<DataByokSeatId, SeatBadgeDescriptor | null> {
  return {
    'customer-kyc': erasureRequested ? { text: 'Erasure Sent', tone: 'amber' } : null,
    'ai-analyst': null,
    'dpo-kms':
      erasureRequested && !isKeyRevoked
        ? { text: '1 Request', tone: 'amber', pulse: true }
        : null
  };
}

export function getDataByokActionGates(params: {
  isBusy: boolean;
  isKeyRevoked: boolean;
  erasureRequested: boolean;
}): DataByokActionGates {
  return {
    canEncryptEnvelope: !params.isBusy && !params.isKeyRevoked,
    canRequestErasure: !params.erasureRequested,
    canRevokeKek: !params.isBusy && !params.isKeyRevoked
  };
}

export function getEnvelopeStatusBadge(isKeyRevoked: boolean): StatusBadgeDescriptor {
  return isKeyRevoked
    ? { label: 'KEY REVOKED', tone: 'crimson' }
    : { label: 'ENCRYPTED', tone: 'emerald' };
}

export function getTenantKekBadge(isRevoked: boolean): StatusBadgeDescriptor {
  return isRevoked
    ? { label: 'REVOKED', tone: 'crimson' }
    : { label: 'ACTIVE', tone: 'emerald' };
}
