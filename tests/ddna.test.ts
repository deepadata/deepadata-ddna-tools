/**
 * Tests for deepadata-ddna-tools
 */

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  seal,
  verify,
  inspect,
  inspectJson,
  keygen,
  deriveKeyPair,
  keyToHex,
  hexToKey,
  publicKeyToDid,
  didToPublicKey,
  isValidDidUrl,
} from '../src/lib/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Test vectors
const VECTORS_DIR = path.join(__dirname, 'vectors');
const TEST_KEYS_PATH = path.join(VECTORS_DIR, 'test-keys.json');
const MINIMAL_EDM_PATH = path.join(VECTORS_DIR, 'minimal.edm.json');

interface TestKeys {
  privateKey: string;
  publicKey: string;
  did: string;
}

let testKeys: TestKeys;
let minimalEdm: object;

beforeAll(() => {
  testKeys = JSON.parse(fs.readFileSync(TEST_KEYS_PATH, 'utf-8'));
  minimalEdm = JSON.parse(fs.readFileSync(MINIMAL_EDM_PATH, 'utf-8'));
});

// ============================================================================
// KEY GENERATION TESTS
// ============================================================================

describe('keygen', () => {
  it('should generate valid key pair', () => {
    const keys = keygen();

    expect(keys.privateKey).toBeInstanceOf(Uint8Array);
    expect(keys.publicKey).toBeInstanceOf(Uint8Array);
    expect(keys.privateKey.length).toBe(32);
    expect(keys.publicKey.length).toBe(32);
    expect(keys.did).toMatch(/^did:key:z6Mk/);
  });

  it('should generate unique keys each time', () => {
    const keys1 = keygen();
    const keys2 = keygen();

    expect(keyToHex(keys1.privateKey)).not.toBe(keyToHex(keys2.privateKey));
    expect(keys1.did).not.toBe(keys2.did);
  });

  it('should derive correct key pair from private key', () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const derived = deriveKeyPair(privateKey);

    expect(keyToHex(derived.publicKey)).toBe(testKeys.publicKey);
    expect(derived.did).toBe(testKeys.did);
  });
});

// ============================================================================
// DID UTILITIES TESTS
// ============================================================================

describe('DID utilities', () => {
  it('should encode public key to did:key', () => {
    const publicKey = hexToKey(testKeys.publicKey);
    const did = publicKeyToDid(publicKey);

    expect(did).toBe(testKeys.did);
  });

  it('should decode did:key to public key', () => {
    const publicKey = didToPublicKey(testKeys.did);
    const hex = keyToHex(publicKey);

    expect(hex).toBe(testKeys.publicKey);
  });

  it('should round-trip encode/decode', () => {
    const keys = keygen();
    const did = publicKeyToDid(keys.publicKey);
    const decoded = didToPublicKey(did);

    expect(keyToHex(decoded)).toBe(keyToHex(keys.publicKey));
  });

  it('should validate did:key format', () => {
    expect(isValidDidUrl(testKeys.did)).toBe(true);
    expect(isValidDidUrl('did:key:invalid')).toBe(false);
    expect(isValidDidUrl('did:web:example.com')).toBe(true);
    expect(isValidDidUrl('not-a-did')).toBe(false);
  });

  it('should reject invalid public key length', () => {
    expect(() => publicKeyToDid(new Uint8Array(16))).toThrow('Invalid public key length');
  });

  it('should reject invalid did:key format', () => {
    expect(() => didToPublicKey('did:web:example.com')).toThrow('Invalid did:key format');
  });
});

// ============================================================================
// SEAL TESTS
// ============================================================================

describe('seal', () => {
  it('should seal minimal EDM payload', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    expect(envelope).toHaveProperty('ddna_header');
    expect(envelope).toHaveProperty('edm_payload');
    expect(envelope).toHaveProperty('proof');

    expect(envelope.ddna_header.ddna_version).toBe('1.1');
    expect(envelope.proof.type).toBe('DataIntegrityProof');
    expect(envelope.proof.cryptosuite).toBe('eddsa-jcs-2022');
    expect(envelope.proof.proofPurpose).toBe('assertionMethod');
    expect(envelope.proof.proofValue).toMatch(/^z/);
  });

  it('should include verification method in proof', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    expect(envelope.proof.verificationMethod).toBe(testKeys.did);
  });

  it('should extract governance from payload', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    expect(envelope.ddna_header.jurisdiction).toBe('AU');
    expect(envelope.ddna_header.exportability).toBe('allowed');
  });

  it('should reject invalid EDM payload', async () => {
    const privateKey = hexToKey(testKeys.privateKey);

    // Missing meta
    await expect(seal({ core: {} }, privateKey, testKeys.did)).rejects.toThrow(
      "missing required domain 'meta'"
    );

    // Missing core
    await expect(seal({ meta: {} }, privateKey, testKeys.did)).rejects.toThrow(
      "missing required domain 'core'"
    );
  });

  it('should reject invalid private key', async () => {
    const shortKey = new Uint8Array(16);

    await expect(seal(minimalEdm, shortKey, testKeys.did)).rejects.toThrow(
      'Invalid private key length'
    );
  });

  it('should reject invalid DID', async () => {
    const privateKey = hexToKey(testKeys.privateKey);

    await expect(seal(minimalEdm, privateKey, 'invalid-did')).rejects.toThrow(
      'Invalid verification method'
    );
  });

  it('should allow custom options', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did, {
      header: { jurisdiction: 'US' },
      expires: '2027-01-01T00:00:00Z',
    });

    expect(envelope.ddna_header.jurisdiction).toBe('US');
    expect(envelope.proof.expires).toBe('2027-01-01T00:00:00Z');
  });
});

// ============================================================================
// VERIFY TESTS
// ============================================================================

describe('verify', () => {
  it('should verify sealed envelope', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    const result = await verify(envelope);

    expect(result.valid).toBe(true);
    expect(result.verificationMethod).toBe(testKeys.did);
  });

  it('should detect tampered payload', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    // Tamper with payload
    (envelope.edm_payload as Record<string, unknown>).tampered = true;

    const result = await verify(envelope);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('verification failed');
  });

  it('should detect tampered header', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    // Tamper with header
    envelope.ddna_header.jurisdiction = 'XX';

    const result = await verify(envelope);

    expect(result.valid).toBe(false);
  });

  it('should detect tampered proof', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    // Tamper with proof created timestamp
    envelope.proof.created = '2020-01-01T00:00:00Z';

    const result = await verify(envelope);

    expect(result.valid).toBe(false);
  });

  it('should reject invalid envelope structure', async () => {
    const result = await verify({ invalid: 'structure' });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('missing');
  });

  it('should reject invalid proof structure', async () => {
    const result = await verify({
      ddna_header: {},
      edm_payload: {},
      proof: { type: 'wrong' },
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('DataIntegrityProof');
  });

  it('should handle expired proofs', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did, {
      expires: '2020-01-01T00:00:00Z',
    });

    const result = await verify(envelope);

    expect(result.valid).toBe(false);
    expect(result.reason).toContain('expired');
  });

  it('should skip timestamp check when requested', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did, {
      expires: '2020-01-01T00:00:00Z',
    });

    const result = await verify(envelope, { skipTimestampCheck: true });

    // Should be valid because we skip the timestamp check
    expect(result.valid).toBe(true);
  });
});

// ============================================================================
// INSPECT TESTS
// ============================================================================

describe('inspect', () => {
  it('should produce human-readable output', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    const output = await inspect(envelope);

    expect(output).toContain('.ddna envelope');
    expect(output).toContain('Signed by:');
    expect(output).toContain('Jurisdiction:');
    expect(output).toContain('VALID');
  });

  it('should produce JSON output', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    const result = (await inspectJson(envelope)) as Record<string, unknown>;

    expect(result).toHaveProperty('inspection');
    expect(result).toHaveProperty('envelope');
    expect(result).toHaveProperty('governance');
    expect(result).toHaveProperty('proof');
  });

  it('should show invalid signature status', async () => {
    const privateKey = hexToKey(testKeys.privateKey);
    const envelope = await seal(minimalEdm, privateKey, testKeys.did);

    // Tamper
    (envelope.edm_payload as Record<string, unknown>).tampered = true;

    const output = await inspect(envelope);

    expect(output).toContain('INVALID');
  });
});

// ============================================================================
// ROUND-TRIP TESTS
// ============================================================================

describe('round-trip', () => {
  it('should seal and verify successfully', async () => {
    // Generate fresh keys
    const keys = keygen();

    // Seal
    const envelope = await seal(minimalEdm, keys.privateKey, keys.did);

    // Verify
    const result = await verify(envelope);

    expect(result.valid).toBe(true);
    expect(result.verificationMethod).toBe(keys.did);
  });

  it('should work with multiple sealing operations', async () => {
    const keys = keygen();

    // Seal multiple times
    const envelope1 = await seal(minimalEdm, keys.privateKey, keys.did);
    const envelope2 = await seal(minimalEdm, keys.privateKey, keys.did);

    // Both should verify
    expect((await verify(envelope1)).valid).toBe(true);
    expect((await verify(envelope2)).valid).toBe(true);

    // Signatures may differ (due to timestamp) but both are valid
  });

  it('should verify with deterministic timestamps', async () => {
    const keys = keygen();
    const timestamp = '2026-01-15T10:00:00.000Z';

    // Must provide both proof.created and header.created_at for deterministic signatures
    const sealOptions = {
      created: timestamp,
      header: { created_at: timestamp } as Record<string, unknown>,
    };

    const envelope1 = await seal(minimalEdm, keys.privateKey, keys.did, sealOptions);
    const envelope2 = await seal(minimalEdm, keys.privateKey, keys.did, sealOptions);

    // With same timestamps (both proof and header), signatures should be identical
    expect(envelope1.proof.proofValue).toBe(envelope2.proof.proofValue);

    // Both should verify
    expect((await verify(envelope1, { skipTimestampCheck: true })).valid).toBe(true);
    expect((await verify(envelope2, { skipTimestampCheck: true })).valid).toBe(true);
  });
});

// ============================================================================
// HEX ENCODING TESTS
// ============================================================================

describe('hex encoding', () => {
  it('should encode key to hex', () => {
    const key = new Uint8Array([0x01, 0x02, 0xff, 0x00]);
    const hex = keyToHex(key);

    expect(hex).toBe('0102ff00');
  });

  it('should decode hex to key', () => {
    const hex = '0102ff00';
    const key = hexToKey(hex);

    expect(Array.from(key)).toEqual([0x01, 0x02, 0xff, 0x00]);
  });

  it('should handle 0x prefix', () => {
    const hex = '0x0102ff00';
    const key = hexToKey(hex);

    expect(Array.from(key)).toEqual([0x01, 0x02, 0xff, 0x00]);
  });

  it('should round-trip encode/decode', () => {
    const original = new Uint8Array(32);
    crypto.getRandomValues(original);

    const hex = keyToHex(original);
    const decoded = hexToKey(hex);

    expect(keyToHex(decoded)).toBe(hex);
  });

  it('should reject invalid hex', () => {
    expect(() => hexToKey('xyz')).toThrow('Invalid hex');
    expect(() => hexToKey('123')).toThrow('odd number');
  });
});
