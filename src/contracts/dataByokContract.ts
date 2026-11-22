export type DlpRuleId = 'DLP-001' | 'DLP-002' | 'DLP-003' | 'DLP-004';

export type DlpClassification = 'PCI' | 'PII' | 'SECRET';

export type DlpAction = 'TOKENIZE' | 'REDACT' | 'BLOCK';

export type Lab7Stage = 1 | 2 | 3;

export type GateVisualState = 'pending' | 'running' | 'passed' | 'blocked' | 'warning';

export interface DlpRuleDefinition {
  id: DlpRuleId;
  name: string;
  classification: DlpClassification;
  action: DlpAction;
  description: string;
  patternSource: string;
  flags?: string;
  tokenPrefix?: string;
}

export interface DlpFinding {
  rule_id: DlpRuleId;
  rule_name: string;
  classification: DlpClassification;
  action: DlpAction;
  field_path: string;
  original_preview: string;
  replacement: string;
}

export interface DlpEvaluationResult {
  correlation_id: string;
  traceparent: string;
  status: 'PASS' | 'BLOCK';
  http_status: 200 | 403;
  findings: DlpFinding[];
  raw_payload: Record<string, string>;
  sanitized_payload: Record<string, string>;
  blocked_reason?: string;
  evaluated_at: string;
}

export interface TenantKeyState {
  tenant_id: string;
  key_id: string;
  key_version: number;
  algorithm: 'AES-KW';
  length: 256;
  extractable: false;
  status: 'ACTIVE' | 'REVOKED';
  created_at: string;
  revoked_at?: string;
}

export interface EncryptedEnvelopeRecord {
  record_id: string;
  tenant_id: string;
  key_id: string;
  key_version: number;
  dek_algorithm: 'AES-GCM';
  dek_length: 256;
  kek_algorithm: 'AES-KW';
  iv_b64: string;
  wrapped_dek_b64: string;
  ciphertext_b64: string;
  aad_b64: string;
  aad_text: string;
  dlp_findings: DlpFinding[];
  encrypted_at: string;
  correlation_id: string;
  traceparent: string;
}

export type DecryptStatus =
  | 'DECRYPTED'
  | 'CRYPTO_SHREDDED_KEY_REVOKED'
  | 'TENANT_KEY_MISMATCH'
  | 'INTEGRITY_CHECK_FAILED';

export interface DecryptVerificationResult {
  ok: boolean;
  status: DecryptStatus;
  error_code?: string;
  error_detail?: string;
  decrypted_payload?: Record<string, string>;
  correlation_id: string;
  traceparent: string;
  verified_at: string;
}

export type DataByokSeatId = 'customer-kyc' | 'ai-analyst' | 'dpo-kms';

export type DataByokApiAction =
  | 'tokenize'
  | 'store_envelope'
  | 'revoke_kek'
  | 'revoke_shared_kek_trap';

export interface SharedKeyTrapResult {
  status: 'SHARED_KEY_BLAST_RADIUS_BLOCKED';
  http_status: 409;
  error_code: 'SHARED_KEK_COLLATERAL_BLAST_RADIUS';
  target_tenant: string;
  collateral_tenants_affected: string[];
  collateral_records_at_risk: number;
  invariant: 'BYOK_PER_TENANT_KEK_ISOLATION';
  message: string;
  correlation_id: string;
  traceparent: string;
  triggered_at: string;
}

export interface SiblingTenantSummary {
  tenant_id: string;
  region_label: string;
  key_id: string;
  records_count: number;
  status: 'ACTIVE' | 'REVOKED';
}

export type DataByokAuditEventType =
  | 'DLP_TOKENIZED'
  | 'DLP_SECRET_BLOCKED'
  | 'ENVELOPE_ENCRYPTED'
  | 'ERASURE_REQUESTED'
  | 'KEK_REVOKED'
  | 'SHARED_KEY_BLAST_RADIUS_TRAPPED'
  | 'CRYPTO_SHRED_VERIFIED'
  | 'TENANT_MISMATCH_BLOCKED'
  | 'INTEGRITY_CHECK_FAILED'
  | 'DECRYPT_SUCCEEDED'
  | 'STATE_RESET';

export interface DataByokAuditEvent {
  id: string;
  timestamp: string;
  stage: Lab7Stage;
  event_type: DataByokAuditEventType;
  severity: 'INFO' | 'SUCCESS' | 'WARN' | 'CRITICAL';
  title: string;
  detail: string;
  correlation_id: string;
  traceparent: string;
  metadata: Record<string, unknown>;
}

export interface SamplePayloadPreset {
  id: string;
  label: string;
  description: string;
  is_attack?: boolean;
  attack_tag?: string;
  payload: Record<string, string>;
}

/**
 * Deterministic DLP rules aligned with agent-governance/policies/dlp-classification.json
 * and Security Architect Contract & Security Spec (#5).
 */
export const LAB7_DLP_RULES: DlpRuleDefinition[] = [
  {
    id: 'DLP-003',
    name: 'API_SECRET',
    classification: 'SECRET',
    action: 'BLOCK',
    description: 'Fail-closed block for raw API keys, bearer tokens, or AWS AKIA credentials.',
    patternSource:
      '(?:api_key|token|bearer|secret)\\s*[:=]\\s*[\'"]?([a-zA-Z0-9_\\-\\.]{16,})|\\bAKIA[0-9A-Z]{16}\\b',
    flags: 'gi'
  },
  {
    id: 'DLP-001',
    name: 'PCI_PAN',
    classification: 'PCI',
    action: 'TOKENIZE',
    description: 'Tokenize Visa, Mastercard, and Amex primary account numbers at the edge.',
    patternSource: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b',
    flags: 'g',
    tokenPrefix: 'tok_pan_'
  },
  {
    id: 'DLP-002',
    name: 'SSN',
    classification: 'PII',
    action: 'TOKENIZE',
    description: 'Tokenize US Social Security Numbers before AI inference or storage.',
    patternSource: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
    flags: 'g',
    tokenPrefix: 'tok_ssn_'
  },
  {
    id: 'DLP-004',
    name: 'NRIC_MYKAD',
    classification: 'PII',
    action: 'TOKENIZE',
    description: 'Tokenize Singapore NRIC ([STFGM]xxxxxxxX) and Malaysia MyKad (xxxxxx-xx-xxxx).',
    patternSource: '\\b(?:[STFGM]\\d{7}[A-Z]|\\d{6}-\\d{2}-\\d{4})\\b',
    flags: 'g',
    tokenPrefix: 'tok_nric_'
  }
];

export const LAB7_SAMPLE_PRESETS: SamplePayloadPreset[] = [
  {
    id: 'apac-customer-kyc',
    label: 'APAC Customer KYC + Payment',
    description: 'Contains SG NRIC, US SSN, and Visa PAN — safe to tokenize at the edge.',
    payload: {
      customer_name: 'Mei-Ling Tan',
      national_id: 'S8812345A',
      tax_ssn: '123-45-6789',
      payment_card: '4111111111111234',
      ai_prompt: 'Summarize KYC risk tier and verify settlement eligibility for customer.'
    }
  },
  {
    id: 'mykad-remittance',
    label: 'MY Cross-Border Remittance',
    description: 'Contains Malaysia MyKad and Mastercard PAN — tokenized before storage.',
    payload: {
      customer_name: 'Arif Rahman',
      national_id: '900412-14-5678',
      tax_ssn: '987-65-4321',
      payment_card: '5500000000000004',
      ai_prompt: 'Evaluate cross-border remittance compliance and AML screening summary.'
    }
  },
  {
    id: 'attack-7a-secret-leak',
    label: 'Scenario 7A: Unmasked Secret Leak',
    description: 'Injects raw api_key and AWS AKIA key — must fail-closed (HTTP 403) at Edge DLP.',
    is_attack: true,
    attack_tag: '7A',
    payload: {
      customer_name: 'Test Attacker',
      national_id: 'S9123456B',
      tax_ssn: '123-45-6789',
      payment_card: '4111111111111234',
      ai_prompt: 'Forward this to LLM: api_key=sk_live_99887766554433221100 and AKIAIOSFODNN7EXAMPLE'
    }
  }
];
