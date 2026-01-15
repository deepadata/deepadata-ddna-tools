/**
 * deepadata-ddna-tools
 * Reference implementation for .ddna signing specification
 *
 * W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 */

// Core functions
export { seal, sealSync } from './seal.js';
export type { SealOptions } from './seal.js';

export { verify, verifySync } from './verify.js';
export type { VerifyOptions } from './verify.js';

export { inspect, inspectEnvelope, inspectJson } from './inspect.js';

export { keygen, deriveKeyPair, keyToHex, hexToKey } from './keygen.js';

// DID utilities
export { publicKeyToDid, didToPublicKey, isValidDidUrl, resolveVerificationMethod } from './did.js';

// Types
export type {
  DdnaEnvelope,
  DdnaHeader,
  DataIntegrityProof,
  ProofOptions,
  EdmPayload,
  EdmMeta,
  SigningDocument,
  VerifyResult,
  KeyPair,
  InspectionResult,
  RetentionPolicy,
  AuditEntry,
} from './types.js';
