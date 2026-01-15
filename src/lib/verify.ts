/**
 * Verification: .ddna envelope -> validity result
 * Verifies W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import canonicalize from 'canonicalize';
import { base58btc } from 'multiformats/bases/base58';
import { resolveVerificationMethod } from './did.js';
import type {
  DdnaEnvelope,
  DataIntegrityProof,
  ProofOptions,
  SigningDocument,
  VerifyResult,
} from './types.js';

// Configure ed25519 to use sha512
ed25519.etc.sha512Sync = (...msgs) => {
  const h = sha512.create();
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

/**
 * Validate envelope structure
 */
function validateEnvelopeStructure(envelope: unknown): asserts envelope is DdnaEnvelope {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('Invalid envelope: must be an object');
  }

  const e = envelope as Record<string, unknown>;

  if (!e.ddna_header || typeof e.ddna_header !== 'object') {
    throw new Error('Invalid envelope: missing ddna_header');
  }

  if (!e.edm_payload || typeof e.edm_payload !== 'object') {
    throw new Error('Invalid envelope: missing edm_payload');
  }

  if (!e.proof) {
    throw new Error('Invalid envelope: missing proof');
  }
}

/**
 * Validate proof structure according to spec
 */
function validateProofStructure(proof: unknown): asserts proof is DataIntegrityProof {
  if (!proof || typeof proof !== 'object') {
    throw new Error("Invalid proof structure: missing field 'proof'");
  }

  const p = proof as Record<string, unknown>;

  if (p.type !== 'DataIntegrityProof') {
    throw new Error(`Invalid proof structure: type must be "DataIntegrityProof", got "${p.type}"`);
  }

  if (p.cryptosuite !== 'eddsa-jcs-2022') {
    throw new Error(
      `Invalid proof structure: cryptosuite must be "eddsa-jcs-2022", got "${p.cryptosuite}"`
    );
  }

  if (!p.created || typeof p.created !== 'string') {
    throw new Error("Invalid proof structure: missing field 'created'");
  }

  // Validate ISO 8601 timestamp
  const createdDate = new Date(p.created);
  if (isNaN(createdDate.getTime())) {
    throw new Error(`Invalid proof structure: 'created' is not a valid ISO 8601 timestamp`);
  }

  if (!p.verificationMethod || typeof p.verificationMethod !== 'string') {
    throw new Error("Invalid proof structure: missing field 'verificationMethod'");
  }

  if (p.proofPurpose !== 'assertionMethod') {
    throw new Error(
      `Invalid proof structure: proofPurpose must be "assertionMethod", got "${p.proofPurpose}"`
    );
  }

  if (!p.proofValue || typeof p.proofValue !== 'string') {
    throw new Error("Invalid proof structure: missing field 'proofValue'");
  }

  if (!p.proofValue.startsWith('z')) {
    throw new Error(
      `Invalid proof structure: proofValue must be multibase base58-btc (prefix 'z')`
    );
  }
}

/**
 * Reconstruct the signing input from envelope
 */
function reconstructSigningInput(
  proofOptions: ProofOptions,
  document: SigningDocument
): Uint8Array {
  // Canonicalize both objects with JCS (RFC 8785)
  const canonicalProofOptions = canonicalize(proofOptions);
  const canonicalDocument = canonicalize(document);

  if (!canonicalProofOptions || !canonicalDocument) {
    throw new Error('Canonicalization failed during verification');
  }

  // Hash each canonical form with SHA-256
  const proofOptionsHash = sha256(new TextEncoder().encode(canonicalProofOptions));
  const documentHash = sha256(new TextEncoder().encode(canonicalDocument));

  // Concatenate hashes (64 bytes total)
  const signingInput = new Uint8Array(64);
  signingInput.set(proofOptionsHash, 0);
  signingInput.set(documentHash, 32);

  return signingInput;
}

/**
 * Extract proof options from a full proof (remove proofValue)
 */
function extractProofOptions(proof: DataIntegrityProof): ProofOptions {
  const { proofValue: _, ...proofOptions } = proof;
  return proofOptions as ProofOptions;
}

/**
 * Optional timestamp validation options
 */
export interface VerifyOptions {
  /** Allow clock skew tolerance in milliseconds (default: 5 minutes) */
  clockSkewMs?: number;
  /** Skip timestamp validation */
  skipTimestampCheck?: boolean;
}

/**
 * Verify a .ddna envelope signature
 *
 * @param envelope - The .ddna envelope to verify
 * @param options - Optional verification options
 * @returns Verification result
 */
export async function verify(
  envelope: object,
  options?: VerifyOptions
): Promise<VerifyResult> {
  const clockSkewMs = options?.clockSkewMs ?? 5 * 60 * 1000; // 5 minutes default

  try {
    // Step 1: Validate envelope structure
    validateEnvelopeStructure(envelope);

    // Step 2: Get the proof (handle single proof or array)
    const proofArray = Array.isArray(envelope.proof) ? envelope.proof : [envelope.proof];

    // For now, verify the first proof only
    // Future: support proof chains
    const proof = proofArray[0];
    validateProofStructure(proof);

    // Step 3: Optional timestamp checks
    if (!options?.skipTimestampCheck) {
      const now = Date.now();
      const createdTime = new Date(proof.created).getTime();

      // Check if created is too far in the future
      if (createdTime > now + clockSkewMs) {
        return {
          valid: false,
          reason: `Proof created timestamp is in the future: ${proof.created}`,
          verificationMethod: proof.verificationMethod,
          created: proof.created,
        };
      }

      // Check if proof has expired
      if (proof.expires) {
        const expiresTime = new Date(proof.expires).getTime();
        if (now > expiresTime + clockSkewMs) {
          return {
            valid: false,
            reason: `Proof has expired: ${proof.expires}`,
            verificationMethod: proof.verificationMethod,
            created: proof.created,
          };
        }
      }
    }

    // Step 4: Resolve verification method to get public key
    let publicKey: Uint8Array;
    try {
      publicKey = await resolveVerificationMethod(proof.verificationMethod);
    } catch (error) {
      return {
        valid: false,
        reason: `Failed to resolve verification method: ${error instanceof Error ? error.message : error}`,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    // Step 5: Reconstruct the document (without proof)
    const document: SigningDocument = {
      ddna_header: envelope.ddna_header,
      edm_payload: envelope.edm_payload,
    };

    // Step 6: Extract proof options and reconstruct signing input
    const proofOptions = extractProofOptions(proof);
    const signingInput = reconstructSigningInput(proofOptions, document);

    // Step 7: Decode the signature from multibase base58-btc
    let signature: Uint8Array;
    try {
      signature = base58btc.decode(proof.proofValue);
    } catch (error) {
      return {
        valid: false,
        reason: `Failed to decode proofValue: ${error instanceof Error ? error.message : error}`,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    // Verify signature length
    if (signature.length !== 64) {
      return {
        valid: false,
        reason: `Invalid signature length: expected 64 bytes, got ${signature.length}`,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    // Step 8: Verify the signature
    const isValid = await ed25519.verifyAsync(signature, signingInput, publicKey);

    if (isValid) {
      return {
        valid: true,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    } else {
      return {
        valid: false,
        reason: 'Signature verification failed',
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Synchronous verification (for environments that support it)
 */
export function verifySync(envelope: object, options?: VerifyOptions): VerifyResult {
  const clockSkewMs = options?.clockSkewMs ?? 5 * 60 * 1000;

  try {
    validateEnvelopeStructure(envelope);

    const proofArray = Array.isArray(envelope.proof) ? envelope.proof : [envelope.proof];
    const proof = proofArray[0];
    validateProofStructure(proof);

    if (!options?.skipTimestampCheck) {
      const now = Date.now();
      const createdTime = new Date(proof.created).getTime();

      if (createdTime > now + clockSkewMs) {
        return {
          valid: false,
          reason: `Proof created timestamp is in the future: ${proof.created}`,
          verificationMethod: proof.verificationMethod,
          created: proof.created,
        };
      }

      if (proof.expires) {
        const expiresTime = new Date(proof.expires).getTime();
        if (now > expiresTime + clockSkewMs) {
          return {
            valid: false,
            reason: `Proof has expired: ${proof.expires}`,
            verificationMethod: proof.verificationMethod,
            created: proof.created,
          };
        }
      }
    }

    // For sync version, we need to handle DID resolution synchronously
    // This only works for did:key which doesn't require network
    if (!proof.verificationMethod.startsWith('did:key:')) {
      return {
        valid: false,
        reason: 'Synchronous verification only supports did:key method',
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    // Import did utilities synchronously
    const { didToPublicKey } = require('./did.js');
    const didPart = proof.verificationMethod.split('#')[0];
    const publicKey = didToPublicKey(didPart);

    const document: SigningDocument = {
      ddna_header: envelope.ddna_header,
      edm_payload: envelope.edm_payload,
    };

    const proofOptions = extractProofOptions(proof);
    const signingInput = reconstructSigningInput(proofOptions, document);

    const signature = base58btc.decode(proof.proofValue);
    if (signature.length !== 64) {
      return {
        valid: false,
        reason: `Invalid signature length: expected 64 bytes, got ${signature.length}`,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    const isValid = ed25519.verify(signature, signingInput, publicKey);

    return {
      valid: isValid,
      reason: isValid ? undefined : 'Signature verification failed',
      verificationMethod: proof.verificationMethod,
      created: proof.created,
    };
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}
