/**
 * DID utilities for did:key format
 * Implements Ed25519 public key encoding/decoding as did:key
 */

import { base58btc } from 'multiformats/bases/base58';

// Multicodec prefix for Ed25519 public key (0xed01)
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Encode an Ed25519 public key as a did:key identifier
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @returns did:key identifier string
 */
export function publicKeyToDid(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKey.length}`);
  }

  // Prepend multicodec prefix
  const multicodecKey = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + publicKey.length);
  multicodecKey.set(ED25519_MULTICODEC_PREFIX, 0);
  multicodecKey.set(publicKey, ED25519_MULTICODEC_PREFIX.length);

  // Encode as base58-btc with 'z' prefix
  const encoded = base58btc.encode(multicodecKey);

  return `did:key:${encoded}`;
}

/**
 * Decode a did:key identifier to extract the Ed25519 public key
 *
 * @param did - did:key identifier string
 * @returns 32-byte Ed25519 public key
 */
export function didToPublicKey(did: string): Uint8Array {
  // Validate did:key format
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Invalid did:key format: must start with "did:key:z", got "${did.slice(0, 20)}..."`);
  }

  // Extract the multibase-encoded part (everything after "did:key:")
  const multibaseKey = did.slice(8);

  // Decode from base58-btc
  let decoded: Uint8Array;
  try {
    decoded = base58btc.decode(multibaseKey);
  } catch (error) {
    throw new Error(`Invalid base58-btc encoding in did:key: ${error}`);
  }

  // Verify multicodec prefix
  if (decoded.length < ED25519_MULTICODEC_PREFIX.length) {
    throw new Error('Invalid did:key: decoded value too short');
  }

  if (decoded[0] !== ED25519_MULTICODEC_PREFIX[0] || decoded[1] !== ED25519_MULTICODEC_PREFIX[1]) {
    throw new Error(
      `Invalid multicodec prefix: expected Ed25519 (0xed01), got 0x${decoded[0].toString(16)}${decoded[1].toString(16)}`
    );
  }

  // Extract the 32-byte public key
  const publicKey = decoded.slice(ED25519_MULTICODEC_PREFIX.length);

  if (publicKey.length !== 32) {
    throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKey.length}`);
  }

  return publicKey;
}

/**
 * Validate a DID URL format
 * Currently supports did:key only
 *
 * @param didUrl - DID URL to validate
 * @returns true if valid
 */
export function isValidDidUrl(didUrl: string): boolean {
  // Support did:key format
  if (didUrl.startsWith('did:key:z')) {
    try {
      didToPublicKey(didUrl);
      return true;
    } catch {
      return false;
    }
  }

  // Support did:web format (basic validation only)
  if (didUrl.startsWith('did:web:')) {
    // Basic format check: did:web:<domain>#<key-id> or did:web:<domain>
    const remainder = didUrl.slice(8);
    return remainder.length > 0 && /^[a-zA-Z0-9.-]+/.test(remainder);
  }

  return false;
}

/**
 * Resolve a verification method to a public key
 * Currently only supports did:key (self-contained)
 *
 * @param verificationMethod - DID URL
 * @returns 32-byte Ed25519 public key
 */
export async function resolveVerificationMethod(verificationMethod: string): Promise<Uint8Array> {
  // Handle did:key (self-contained, no network required)
  if (verificationMethod.startsWith('did:key:')) {
    // Strip any fragment identifier
    const didPart = verificationMethod.split('#')[0];
    return didToPublicKey(didPart);
  }

  // did:web would require network resolution (future enhancement)
  if (verificationMethod.startsWith('did:web:')) {
    throw new Error(
      'did:web resolution not yet implemented. Use did:key for local verification.'
    );
  }

  throw new Error(`Unsupported DID method: ${verificationMethod}`);
}
