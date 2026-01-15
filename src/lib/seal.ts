/**
 * Sealing: EDM artifact -> .ddna envelope
 * Implements W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import canonicalize from 'canonicalize';
import { base58btc } from 'multiformats/bases/base58';
import { isValidDidUrl } from './did.js';
import type {
  EdmPayload,
  DdnaHeader,
  DdnaEnvelope,
  SigningDocument,
  ProofOptions,
  DataIntegrityProof,
} from './types.js';

// Configure ed25519 to use sha512
ed25519.etc.sha512Sync = (...msgs) => {
  const h = sha512.create();
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

/**
 * Deep clone an object using JSON serialization
 * This ensures the envelope payload is isolated from the input
 */
function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

/**
 * Validate EDM payload structure
 *
 * @param payload - EDM payload to validate
 * @throws Error if payload is invalid
 */
function validateEdmPayload(payload: unknown): asserts payload is EdmPayload {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid EDM payload: must be an object');
  }

  const p = payload as Record<string, unknown>;

  // Check for required domains (meta and core are typically required)
  if (!p.meta || typeof p.meta !== 'object') {
    throw new Error("Invalid EDM payload: missing required domain 'meta'");
  }

  if (!p.core || typeof p.core !== 'object') {
    throw new Error("Invalid EDM payload: missing required domain 'core'");
  }
}

/**
 * Extract governance fields from EDM payload to construct ddna_header
 * Uses EDM v0.4.0 canonical field names with backward compatibility
 *
 * @param payload - EDM payload
 * @param options - Optional header overrides
 * @returns Constructed ddna_header
 */
function constructDdnaHeader(
  payload: EdmPayload,
  options?: Partial<DdnaHeader>
): DdnaHeader {
  const meta = payload.meta || {};
  const governance = payload.governance as Record<string, unknown> | undefined;

  // Determine EDM version from payload
  // Canonical v0.4.0 uses meta.version, legacy uses meta.schema_version
  const rawVersion = (meta.version as string) ||
    (meta.schema_version as string) ||
    '0.4.0';
  // Normalize: strip "edm.v" prefix if present
  const edmVersion = rawVersion.replace(/^edm\.v/, '');

  // payload_type uses the full schema identifier (e.g., "edm.v0.4.0")
  const payloadType = `edm.v${edmVersion}`;

  // Extract governance info if present
  const jurisdiction = (governance?.jurisdiction as string) || options?.jurisdiction || 'UNKNOWN';
  const exportability = (governance?.exportability as DdnaHeader['exportability']) ||
    options?.exportability || 'allowed';

  // Consent basis: check meta (canonical v0.4.0 location) first
  const consentBasis = (meta.consent_basis as string) ||
    (governance?.consent_basis as string) ||
    options?.consent_basis ||
    'consent';

  // Owner ID: canonical v0.4.0 uses owner_user_id, legacy uses subject_id
  const ownerUserId = (meta.owner_user_id as string | null) ||
    (meta.subject_id as string | null) ||
    null;

  // Extract retention policy from governance if present
  const govRetention = governance?.retention_policy as Record<string, unknown> | undefined;
  const retentionPolicy: DdnaHeader['retention_policy'] = govRetention
    ? {
        basis: (govRetention.basis as DdnaHeader['retention_policy']['basis']) || 'user_defined',
        ttl_days: (govRetention.ttl_days as number | null) ?? null,
        on_expiry: (govRetention.on_expiry as DdnaHeader['retention_policy']['on_expiry']) || 'soft_delete',
      }
    : {
        basis: 'user_defined',
        ttl_days: null,
        on_expiry: 'soft_delete',
      };

  const header: DdnaHeader = {
    ddna_version: '1.1',
    created_at: new Date().toISOString(),
    edm_version: edmVersion,
    owner_user_id: ownerUserId,
    exportability,
    jurisdiction,
    payload_type: payloadType,
    consent_basis: consentBasis,
    retention_policy: retentionPolicy,
    ...options,
  };

  return header;
}

/**
 * Create signing input according to spec:
 * SHA-256(JCS(proof_options)) || SHA-256(JCS(document))
 *
 * @param proofOptions - Proof options (without proofValue)
 * @param document - Document to sign (ddna_header + edm_payload)
 * @returns 64-byte signing input
 */
function createSigningInput(
  proofOptions: ProofOptions,
  document: SigningDocument
): Uint8Array {
  // Step 1: Canonicalize both objects with JCS (RFC 8785)
  const canonicalProofOptions = canonicalize(proofOptions);
  const canonicalDocument = canonicalize(document);

  if (!canonicalProofOptions || !canonicalDocument) {
    throw new Error('Canonicalization failed');
  }

  // Step 2: Hash each canonical form with SHA-256
  const proofOptionsHash = sha256(new TextEncoder().encode(canonicalProofOptions));
  const documentHash = sha256(new TextEncoder().encode(canonicalDocument));

  // Step 3: Concatenate hashes (64 bytes total)
  const signingInput = new Uint8Array(64);
  signingInput.set(proofOptionsHash, 0);
  signingInput.set(documentHash, 32);

  return signingInput;
}

/**
 * Seal options for customizing the sealing process
 */
export interface SealOptions {
  /** Override ddna_header fields */
  header?: Partial<DdnaHeader>;
  /** Optional proof expiration (ISO 8601) */
  expires?: string;
  /** Optional domain restriction */
  domain?: string;
  /** Optional challenge value */
  challenge?: string;
  /** Optional nonce for replay prevention */
  nonce?: string;
  /** Custom timestamp for created field (ISO 8601) */
  created?: string;
}

/**
 * Seal an EDM payload into a .ddna envelope
 *
 * @param edmPayload - The EDM artifact to seal
 * @param privateKey - 32-byte Ed25519 private key
 * @param verificationMethod - DID URL for the verification method
 * @param options - Optional sealing options
 * @returns Sealed .ddna envelope
 */
export async function seal(
  edmPayload: object,
  privateKey: Uint8Array,
  verificationMethod: string,
  options?: SealOptions
): Promise<DdnaEnvelope> {
  // Step 1: Validate inputs
  validateEdmPayload(edmPayload);

  if (privateKey.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 bytes, got ${privateKey.length}`);
  }

  if (!isValidDidUrl(verificationMethod)) {
    throw new Error(`Invalid verification method: ${verificationMethod}`);
  }

  // Deep clone the payload to isolate it from the input
  const clonedPayload = deepClone(edmPayload) as EdmPayload;

  // Step 2: Construct ddna_header from payload governance fields
  const ddnaHeader = constructDdnaHeader(clonedPayload, options?.header);

  // Step 3: Create document structure (without proof)
  const document: SigningDocument = {
    ddna_header: ddnaHeader,
    edm_payload: clonedPayload,
  };

  // Step 4: Create proof options (all proof fields except proofValue)
  const proofOptions: ProofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: options?.created || new Date().toISOString(),
    verificationMethod,
    proofPurpose: 'assertionMethod',
  };

  // Add optional proof fields
  if (options?.expires) {
    proofOptions.expires = options.expires;
  }
  if (options?.domain) {
    proofOptions.domain = options.domain;
  }
  if (options?.challenge) {
    proofOptions.challenge = options.challenge;
  }
  if (options?.nonce) {
    proofOptions.nonce = options.nonce;
  }

  // Step 5: Create signing input
  const signingInput = createSigningInput(proofOptions, document);

  // Step 6: Sign with Ed25519
  const signature = await ed25519.signAsync(signingInput, privateKey);

  // Step 7: Encode signature as multibase base58-btc (prefix 'z')
  const proofValue = base58btc.encode(signature);

  // Step 8: Assemble complete proof
  const proof: DataIntegrityProof = {
    ...proofOptions,
    proofValue,
  };

  // Step 9: Return complete envelope
  return {
    ddna_header: ddnaHeader,
    edm_payload: clonedPayload,
    proof,
  };
}

/**
 * Seal with synchronous signing (for environments that support it)
 */
export function sealSync(
  edmPayload: object,
  privateKey: Uint8Array,
  verificationMethod: string,
  options?: SealOptions
): DdnaEnvelope {
  // Validate inputs
  validateEdmPayload(edmPayload);

  if (privateKey.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 bytes, got ${privateKey.length}`);
  }

  if (!isValidDidUrl(verificationMethod)) {
    throw new Error(`Invalid verification method: ${verificationMethod}`);
  }

  // Deep clone the payload to isolate it from the input
  const clonedPayload = deepClone(edmPayload) as EdmPayload;

  // Construct header
  const ddnaHeader = constructDdnaHeader(clonedPayload, options?.header);

  // Create document
  const document: SigningDocument = {
    ddna_header: ddnaHeader,
    edm_payload: clonedPayload,
  };

  // Create proof options
  const proofOptions: ProofOptions = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    created: options?.created || new Date().toISOString(),
    verificationMethod,
    proofPurpose: 'assertionMethod',
  };

  if (options?.expires) proofOptions.expires = options.expires;
  if (options?.domain) proofOptions.domain = options.domain;
  if (options?.challenge) proofOptions.challenge = options.challenge;
  if (options?.nonce) proofOptions.nonce = options.nonce;

  // Create signing input and sign
  const signingInput = createSigningInput(proofOptions, document);
  const signature = ed25519.sign(signingInput, privateKey);
  const proofValue = base58btc.encode(signature);

  const proof: DataIntegrityProof = {
    ...proofOptions,
    proofValue,
  };

  return {
    ddna_header: ddnaHeader,
    edm_payload: clonedPayload,
    proof,
  };
}
