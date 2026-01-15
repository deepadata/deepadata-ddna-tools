/**
 * Key generation for Ed25519 in DID format
 * Generates cryptographic key pairs for signing .ddna envelopes
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { publicKeyToDid } from './did.js';
import type { KeyPair } from './types.js';

// Configure ed25519 to use sha512
ed25519.etc.sha512Sync = (...msgs) => {
  const h = sha512.create();
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

/**
 * Generate a new Ed25519 key pair with DID identifier
 *
 * @returns Key pair containing private key, public key, and did:key identifier
 */
export function keygen(): KeyPair {
  // Generate random 32-byte private key
  const privateKey = ed25519.utils.randomPrivateKey();

  // Derive public key from private key
  const publicKey = ed25519.getPublicKey(privateKey);

  // Create did:key identifier
  const did = publicKeyToDid(publicKey);

  return {
    privateKey,
    publicKey,
    did,
  };
}

/**
 * Derive public key and DID from an existing private key
 *
 * @param privateKey - 32-byte Ed25519 private key
 * @returns Key pair containing the provided private key, derived public key, and DID
 */
export function deriveKeyPair(privateKey: Uint8Array): KeyPair {
  if (privateKey.length !== 32) {
    throw new Error(`Invalid private key length: expected 32 bytes, got ${privateKey.length}`);
  }

  const publicKey = ed25519.getPublicKey(privateKey);
  const did = publicKeyToDid(publicKey);

  return {
    privateKey,
    publicKey,
    did,
  };
}

/**
 * Encode a key as hex string for storage
 *
 * @param key - Key bytes to encode
 * @returns Hex-encoded string
 */
export function keyToHex(key: Uint8Array): string {
  return Array.from(key)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Decode a hex string to key bytes
 *
 * @param hex - Hex-encoded string
 * @returns Key bytes
 */
export function hexToKey(hex: string): Uint8Array {
  const cleanHex = hex.replace(/^0x/, '').replace(/\s/g, '');

  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd number of characters');
  }

  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const byte = parseInt(cleanHex.slice(i, i + 2), 16);
    if (isNaN(byte)) {
      throw new Error(`Invalid hex character at position ${i}`);
    }
    bytes[i / 2] = byte;
  }

  return bytes;
}
