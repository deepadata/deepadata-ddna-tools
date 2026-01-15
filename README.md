# deepadata-ddna-tools

Reference implementation for the .ddna signing specification. Creates and verifies W3C Data Integrity Proofs using Ed25519 signatures with JSON Canonicalization Scheme (JCS).

## Features

- **Seal** EDM artifacts into cryptographically signed `.ddna` envelopes
- **Verify** envelope signatures using did:key verification methods
- **Inspect** envelope contents in human-readable or JSON format
- **Generate** Ed25519 key pairs with DID identifiers

## Installation

```bash
npm install -g deepadata-ddna-tools
```

Or use directly with npx:

```bash
npx deepadata-ddna-tools <command>
```

## Quick Start

```bash
# Generate a key pair
ddna keygen --output mykey
# Outputs: mykey.key, mykey.pub, and DID

# Seal an EDM artifact
ddna seal --key mykey.key --did did:key:z6Mk... example.edm.json
# Outputs: example.ddna

# Verify the sealed envelope
ddna verify example.ddna
# Outputs: VALID - Signature verified

# Inspect envelope details
ddna inspect example.ddna
```

## Commands

### `ddna seal`

Seal an EDM artifact into a `.ddna` envelope with a cryptographic signature.

```bash
ddna seal [options] <input>
```

**Arguments:**
- `<input>` - Path to EDM artifact (`.edm.json` or `.json`)

**Options:**
- `-k, --key <path>` - Path to private key file (hex-encoded) **[required]**
- `-d, --did <url>` - DID URL for verification method **[required]**
- `-o, --output <path>` - Output path (default: `<input>.ddna`)
- `--jurisdiction <code>` - Override jurisdiction code (e.g., AU, US)
- `--expires <iso8601>` - Proof expiration timestamp

**Example:**
```bash
ddna seal --key test.key --did did:key:z6MkiTBz1... artifact.edm.json
```

### `ddna verify`

Verify the signature on a `.ddna` envelope.

```bash
ddna verify [options] <input>
```

**Arguments:**
- `<input>` - Path to `.ddna` envelope

**Options:**
- `--skip-timestamp` - Skip timestamp validation

**Example:**
```bash
ddna verify artifact.ddna
# VALID - Signature verified
#   Verification Method: did:key:z6MkiTBz1...
#   Created: 2026-01-15T10:00:00.000Z
```

### `ddna inspect`

Inspect a `.ddna` envelope and display its contents.

```bash
ddna inspect [options] <input>
```

**Arguments:**
- `<input>` - Path to `.ddna` envelope

**Options:**
- `--json` - Output as JSON

**Example:**
```bash
ddna inspect artifact.ddna

Valid .ddna envelope (v1.1)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Signed by: did:key:z6MkiTBz1...uepAQ4HE
Created: 2026-01-15T10:00:00.000Z
Subject: auraid-000000001
Schema: edm.v0.4.0

Governance:
  Jurisdiction: AU
  Retention: user_defined
  Exportability: allowed
  Consent Basis: explicit_consent

Signature: VALID ✓
```

### `ddna keygen`

Generate an Ed25519 key pair with DID identifier.

```bash
ddna keygen [options]
```

**Options:**
- `-o, --output <prefix>` - Output file prefix (creates `<prefix>.key` and `<prefix>.pub`)
- `--json` - Output as JSON to stdout

**Example:**
```bash
ddna keygen --output mykey
# ✓ Key pair generated
#   Private key: mykey.key
#   Public key:  mykey.pub
#   DID:         did:key:z6Mkf5rGMoatrSj1f4QH...
```

## Library Usage

The package can also be used as a library:

```typescript
import {
  seal,
  verify,
  inspect,
  keygen,
  hexToKey,
  keyToHex,
} from 'deepadata-ddna-tools';

// Generate keys
const keys = keygen();
console.log('DID:', keys.did);

// Seal an EDM artifact
const edmPayload = {
  meta: { subject_id: 'user-123', schema_version: 'edm.v0.4.0' },
  core: { emotional_baseline: { valence: 0.5 } },
  governance: { jurisdiction: 'AU' },
};

const envelope = await seal(edmPayload, keys.privateKey, keys.did);

// Verify the envelope
const result = await verify(envelope);
console.log('Valid:', result.valid);

// Inspect
const output = await inspect(envelope);
console.log(output);
```

## Specification

This implementation follows the [DDNA Signing Model Specification](https://github.com/deepadata/deepadata-edm-spec/blob/main/docs/DDNA_SIGNING_MODEL.md).

**Key standards:**
- [W3C Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- [RFC 8785 JSON Canonicalization Scheme](https://datatracker.ietf.org/doc/rfc8785/)
- [RFC 8032 Ed25519 Signatures](https://datatracker.ietf.org/doc/rfc8032/)
- [did:key Method](https://w3c-ccg.github.io/did-method-key/)

## Envelope Structure

A `.ddna` envelope contains three components:

```json
{
  "ddna_header": {
    "ddna_version": "1.1",
    "created_at": "2026-01-15T10:00:00Z",
    "edm_version": "edm.v0.4.0",
    "jurisdiction": "AU",
    "exportability": "allowed",
    ...
  },
  "edm_payload": {
    "meta": { ... },
    "core": { ... },
    ...
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk...",
    "proofPurpose": "assertionMethod",
    "proofValue": "z..."
  }
}
```

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev -- keygen

# Build
npm run build

# Run tests
npm test
```

## License

MIT
