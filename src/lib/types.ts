/**
 * Type definitions for .ddna signing specification
 * W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 */

/**
 * Retention policy for EDM artifacts
 */
export interface RetentionPolicy {
  basis: 'user_defined' | 'legal_hold' | 'regulatory' | 'indefinite';
  ttl_days: number | null;
  on_expiry: 'soft_delete' | 'hard_delete' | 'archive';
}

/**
 * Audit chain entry for lifecycle tracking
 */
export interface AuditEntry {
  timestamp: string;
  event: string;
  agent: string;
  details?: Record<string, unknown>;
}

/**
 * DDNA header containing governance and lifecycle metadata
 */
export interface DdnaHeader {
  ddna_version: string;
  created_at: string;
  edm_version: string;
  owner_user_id: string | null;
  exportability: 'allowed' | 'restricted' | 'prohibited';
  jurisdiction: string;
  payload_type: string;
  consent_basis: string;
  retention_policy: RetentionPolicy;
  masking_rules?: string[];
  audit_chain?: AuditEntry[];
}

/**
 * W3C Data Integrity Proof structure
 */
export interface DataIntegrityProof {
  type: 'DataIntegrityProof';
  cryptosuite: 'eddsa-jcs-2022';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
  expires?: string;
  domain?: string;
  challenge?: string;
  nonce?: string;
  previousProof?: string;
}

/**
 * Proof options (all proof fields except proofValue)
 */
export type ProofOptions = Omit<DataIntegrityProof, 'proofValue'>;

/**
 * EDM payload meta domain
 */
export interface EdmMeta {
  subject_id?: string;
  schema_version?: string;
  consent_timestamp?: string;
  [key: string]: unknown;
}

/**
 * EDM payload structure
 */
export interface EdmPayload {
  meta?: EdmMeta;
  core?: Record<string, unknown>;
  constellation?: Record<string, unknown>;
  milky_way?: Record<string, unknown>;
  gravity?: Record<string, unknown>;
  impulse?: Record<string, unknown>;
  governance?: Record<string, unknown>;
  telemetry?: Record<string, unknown>;
  system?: Record<string, unknown>;
  crosswalks?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Complete .ddna envelope structure
 */
export interface DdnaEnvelope {
  ddna_header: DdnaHeader;
  edm_payload: EdmPayload;
  proof: DataIntegrityProof | DataIntegrityProof[];
}

/**
 * Document structure for signing (without proof)
 */
export interface SigningDocument {
  ddna_header: DdnaHeader;
  edm_payload: EdmPayload;
}

/**
 * Result of signature verification
 */
export interface VerifyResult {
  valid: boolean;
  reason?: string;
  verificationMethod?: string;
  created?: string;
}

/**
 * Key pair in DID format
 */
export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  did: string;
}

/**
 * Inspection result for human-readable output
 */
export interface InspectionResult {
  valid: boolean;
  version: string;
  verificationMethod: string;
  created: string;
  subjectId: string | null;
  schemaVersion: string;
  jurisdiction: string;
  retention: string;
  exportability: string;
  consentBasis: string;
  signatureStatus: 'VALID' | 'INVALID' | 'UNKNOWN';
  invalidReason?: string;
}
