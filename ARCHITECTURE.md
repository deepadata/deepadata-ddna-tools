# Architecture

This document describes the architecture of deepadata-ddna-tools, the reference implementation for the .ddna signing specification.

## Overview

The library implements W3C Data Integrity Proofs using the `eddsa-jcs-2022` cryptosuite. It provides both a CLI and programmatic API for sealing, verifying, and inspecting .ddna envelopes.

## Library Structure

```
src/
├── cli.ts              # Command-line interface
└── lib/
    ├── index.ts        # Public API exports
    ├── types.ts        # TypeScript type definitions
    ├── seal.ts         # Sealing (signing) implementation
    ├── verify.ts       # Verification implementation
    ├── inspect.ts      # Human-readable inspection
    ├── keygen.ts       # Key generation utilities
    └── did.ts          # DID encoding/decoding utilities
```

## Core Modules

### seal.ts

Transforms an EDM payload into a signed .ddna envelope.

**Key functions:**
- `seal(edmPayload, privateKey, verificationMethod, options?)` - Async sealing
- `sealSync(...)` - Synchronous variant

**Responsibilities:**
1. Validate EDM payload structure
2. Construct ddna_header from governance fields
3. Create proof options object
4. Compute signing input via JCS + SHA-256
5. Sign with Ed25519
6. Assemble complete envelope

### verify.ts

Validates the cryptographic integrity of a .ddna envelope.

**Key functions:**
- `verify(envelope, options?)` - Async verification
- `verifySync(...)` - Synchronous variant (did:key only)

**Responsibilities:**
1. Parse and validate envelope structure
2. Validate proof structure
3. Resolve verification method to public key
4. Reconstruct signing input
5. Verify Ed25519 signature
6. Check timestamp constraints

### inspect.ts

Produces human-readable analysis of envelope contents.

**Key functions:**
- `inspect(envelope)` - Human-readable string
- `inspectJson(envelope)` - Structured JSON output
- `inspectEnvelope(envelope)` - Raw inspection result

### keygen.ts

Ed25519 key pair generation with DID support.

**Key functions:**
- `keygen()` - Generate new key pair
- `deriveKeyPair(privateKey)` - Derive from existing private key
- `keyToHex(key)` / `hexToKey(hex)` - Encoding utilities

### did.ts

DID (Decentralized Identifier) utilities.

**Key functions:**
- `publicKeyToDid(publicKey)` - Encode as did:key
- `didToPublicKey(did)` - Decode did:key
- `resolveVerificationMethod(did)` - Resolve to public key
- `isValidDidUrl(did)` - Validation

## Signing Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           SEALING PROCESS                               │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│  EDM Payload │
│   (input)    │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  1. Validate EDM payload structure                           │
│     - Check required domains (meta, core)                    │
│     - Extract governance metadata                            │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  2. Construct ddna_header                                    │
│     - Set ddna_version, created_at                           │
│     - Copy governance fields (jurisdiction, exportability)   │
│     - Set retention_policy                                   │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  3. Create document = { ddna_header, edm_payload }           │
│     (NO proof field at this stage)                           │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  4. Create proof_options (without proofValue)                │
│     - type: "DataIntegrityProof"                             │
│     - cryptosuite: "eddsa-jcs-2022"                          │
│     - created, verificationMethod, proofPurpose              │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  5. Canonicalize with JCS (RFC 8785)                         │
│                                                              │
│     canonical_proof_options = JCS(proof_options)             │
│     canonical_document = JCS(document)                       │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  6. Hash with SHA-256                                        │
│                                                              │
│     proof_options_hash = SHA-256(canonical_proof_options)    │
│     document_hash = SHA-256(canonical_document)              │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  7. Concatenate hashes                                       │
│                                                              │
│     signing_input = proof_options_hash || document_hash      │
│                     (32 bytes)            (32 bytes)         │
│                              = 64 bytes total                │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  8. Sign with Ed25519                                        │
│                                                              │
│     signature = Ed25519_Sign(private_key, signing_input)     │
│                 (64 bytes)                                   │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  9. Encode signature as multibase base58-btc                 │
│                                                              │
│     proofValue = 'z' + base58btc_encode(signature)           │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  10. Assemble complete envelope                              │
│                                                              │
│      {                                                       │
│        ddna_header: { ... },                                 │
│        edm_payload: { ... },                                 │
│        proof: { ...proof_options, proofValue }               │
│      }                                                       │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
                    ┌──────────────────┐
                    │  .ddna Envelope  │
                    │    (output)      │
                    └──────────────────┘
```

## Verification Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         VERIFICATION PROCESS                            │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────────┐
│  .ddna Envelope  │
│     (input)      │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│  1. Parse envelope structure                                 │
│     - Extract ddna_header, edm_payload, proof                │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  2. Validate proof structure                                 │
│     - type == "DataIntegrityProof"                           │
│     - cryptosuite == "eddsa-jcs-2022"                        │
│     - proofPurpose == "assertionMethod"                      │
│     - created is valid ISO 8601                              │
│     - proofValue starts with 'z'                             │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  3. Check timestamps (optional)                              │
│     - created not in future                                  │
│     - expires (if present) not in past                       │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  4. Resolve verification method                              │
│                                                              │
│     did:key:z6Mk... → extract Ed25519 public key             │
│                                                              │
│     (did:web requires network resolution - future)           │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  5. Reconstruct signing input                                │
│                                                              │
│     document = { ddna_header, edm_payload }                  │
│     proof_options = proof - proofValue                       │
│                                                              │
│     signing_input = SHA-256(JCS(proof_options))              │
│                   || SHA-256(JCS(document))                  │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  6. Decode signature                                         │
│                                                              │
│     signature = base58btc_decode(proofValue.slice(1))        │
│                 (remove 'z' prefix, decode 64 bytes)         │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  7. Verify signature                                         │
│                                                              │
│     valid = Ed25519_Verify(public_key, signing_input,        │
│                            signature)                        │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
                      ┌────────┴────────┐
                      │                 │
                      ▼                 ▼
               ┌──────────┐      ┌───────────┐
               │  VALID   │      │  INVALID  │
               └──────────┘      └───────────┘
```

## DID URL Support

### Currently Implemented: did:key

`did:key` is a self-certifying DID method where the public key is encoded directly in the DID identifier. No network resolution is required.

**Format:** `did:key:z6Mk<base58btc-encoded-multicodec-public-key>`

**Encoding:**
1. Prepend multicodec prefix `0xed01` (Ed25519 public key)
2. Encode with base58-btc (adds 'z' prefix)

**Example:**
```
Public Key: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
DID:        did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp
```

### Future Enhancement: did:web

`did:web` allows organizations to host DID documents at well-known URLs, enabling:
- Key rotation
- Multiple verification methods
- Organizational control

**Resolution:**
```
did:web:example.com → https://example.com/.well-known/did.json
did:web:example.com:path:to:doc → https://example.com/path/to/doc/did.json
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `@noble/ed25519` | Ed25519 signing/verification (RFC 8032) |
| `@noble/hashes` | SHA-256 and SHA-512 hashing |
| `canonicalize` | RFC 8785 JSON Canonicalization Scheme |
| `multiformats` | Multibase encoding (base58-btc) |
| `commander` | CLI framework |
| `chalk` | Terminal colors |

## Security Considerations

1. **Private key handling**: Keys are stored as hex-encoded files. Consider using secure enclaves for production.

2. **Canonicalization attacks**: JCS implementation must be compliant to prevent attacks where different JSON representations produce different hashes.

3. **DID resolution**: For `did:web`, HTTPS verification is critical. Compromised resolution enables forgery.

4. **Timestamp validation**: Clock skew tolerance prevents strict timestamp enforcement from causing false negatives.

## Error Handling

The library provides descriptive error messages:

```
Invalid EDM payload: missing required domain 'core'
Invalid private key length: expected 32 bytes, got 16
Invalid proof structure: type must be "DataIntegrityProof"
Signature verification failed
Failed to resolve verification method: did:web resolution not yet implemented
```

## Testing

Test vectors are provided in `tests/vectors/`:
- `test-keys.json` - Reproducible key pair for testing
- `minimal.edm.json` - Minimal valid EDM artifact
- `minimal.ddna` - Reference sealed envelope

Run tests with:
```bash
npm test
```
