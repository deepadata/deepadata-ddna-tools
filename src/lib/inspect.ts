/**
 * Inspection: Human-readable .ddna envelope analysis
 * Provides formatted output for envelope contents and verification status
 */

import { verify } from './verify.js';
import type {
  DdnaEnvelope,
  DdnaHeader,
  DataIntegrityProof,
  InspectionResult,
  EdmPayload,
} from './types.js';

/**
 * Parse and validate envelope structure for inspection
 */
function parseEnvelope(envelope: unknown): DdnaEnvelope | null {
  if (!envelope || typeof envelope !== 'object') {
    return null;
  }

  const e = envelope as Record<string, unknown>;

  if (!e.ddna_header || !e.edm_payload || !e.proof) {
    return null;
  }

  return e as unknown as DdnaEnvelope;
}

/**
 * Get the first proof from envelope (handling array case)
 */
function getFirstProof(envelope: DdnaEnvelope): DataIntegrityProof | null {
  if (Array.isArray(envelope.proof)) {
    return envelope.proof[0] || null;
  }
  return envelope.proof;
}

/**
 * Format retention policy for display
 */
function formatRetention(header: DdnaHeader): string {
  const policy = header.retention_policy;
  if (!policy) return 'undefined';

  let result = policy.basis;
  if (policy.ttl_days !== null) {
    result += ` (${policy.ttl_days} days)`;
  }
  return result;
}

/**
 * Truncate a DID for display (show first and last parts)
 */
function truncateDid(did: string, maxLength = 50): string {
  if (did.length <= maxLength) return did;

  const prefix = did.slice(0, 20);
  const suffix = did.slice(-15);
  return `${prefix}...${suffix}`;
}

/**
 * Inspect a .ddna envelope and return structured result
 *
 * @param envelope - The envelope to inspect
 * @returns Inspection result with all relevant metadata
 */
export async function inspectEnvelope(envelope: object): Promise<InspectionResult> {
  const parsed = parseEnvelope(envelope);

  if (!parsed) {
    return {
      valid: false,
      version: 'unknown',
      verificationMethod: 'unknown',
      created: 'unknown',
      subjectId: null,
      schemaVersion: 'unknown',
      jurisdiction: 'unknown',
      retention: 'unknown',
      exportability: 'unknown',
      consentBasis: 'unknown',
      signatureStatus: 'INVALID',
      invalidReason: 'Invalid envelope structure',
    };
  }

  const header = parsed.ddna_header;
  const payload = parsed.edm_payload as EdmPayload;
  const proof = getFirstProof(parsed);

  // Verify the signature
  const verifyResult = await verify(envelope, { skipTimestampCheck: true });

  return {
    valid: true,
    version: header.ddna_version || 'unknown',
    verificationMethod: proof?.verificationMethod || 'unknown',
    created: proof?.created || header.created_at || 'unknown',
    subjectId: (payload.meta?.subject_id as string) || header.owner_user_id || null,
    schemaVersion: header.edm_version || (payload.meta?.schema_version as string) || 'unknown',
    jurisdiction: header.jurisdiction || 'unknown',
    retention: formatRetention(header),
    exportability: header.exportability || 'unknown',
    consentBasis: header.consent_basis || 'unknown',
    signatureStatus: verifyResult.valid ? 'VALID' : 'INVALID',
    invalidReason: verifyResult.valid ? undefined : verifyResult.reason,
  };
}

/**
 * Generate human-readable inspection output
 *
 * @param envelope - The envelope to inspect
 * @returns Formatted string for terminal display
 */
export async function inspect(envelope: object): Promise<string> {
  const result = await inspectEnvelope(envelope);

  if (!result.valid && result.invalidReason?.includes('Invalid envelope structure')) {
    return `Invalid .ddna envelope
${'='.repeat(41)}
Error: ${result.invalidReason}

The provided file does not appear to be a valid .ddna envelope.
Expected structure: { ddna_header, edm_payload, proof }`;
  }

  const lines: string[] = [];

  // Header
  const statusIcon = result.signatureStatus === 'VALID' ? '(v' + result.version + ')' : '(INVALID)';
  lines.push(`Valid .ddna envelope ${statusIcon}`);
  lines.push('\u2501'.repeat(41)); // ━ box drawing character

  // Core info
  lines.push(`Signed by: ${truncateDid(result.verificationMethod)}`);
  lines.push(`Created: ${result.created}`);
  if (result.subjectId) {
    lines.push(`Subject: ${result.subjectId}`);
  }
  lines.push(`Schema: ${result.schemaVersion}`);

  // Governance section
  lines.push('');
  lines.push('Governance:');
  lines.push(`  Jurisdiction: ${result.jurisdiction}`);
  lines.push(`  Retention: ${result.retention}`);
  lines.push(`  Exportability: ${result.exportability}`);
  lines.push(`  Consent Basis: ${result.consentBasis}`);

  // Signature status
  lines.push('');
  if (result.signatureStatus === 'VALID') {
    lines.push('Signature: VALID \u2713'); // ✓
  } else {
    lines.push('Signature: INVALID \u2717'); // ✗
    if (result.invalidReason) {
      lines.push(`  Reason: ${result.invalidReason}`);
    }
  }

  return lines.join('\n');
}

/**
 * Generate JSON inspection output
 *
 * @param envelope - The envelope to inspect
 * @returns JSON object with inspection details
 */
export async function inspectJson(envelope: object): Promise<object> {
  const result = await inspectEnvelope(envelope);
  const parsed = parseEnvelope(envelope);

  return {
    inspection: {
      valid: result.valid,
      signatureStatus: result.signatureStatus,
      invalidReason: result.invalidReason,
    },
    envelope: {
      version: result.version,
      created: result.created,
      verificationMethod: result.verificationMethod,
    },
    subject: {
      id: result.subjectId,
      schemaVersion: result.schemaVersion,
    },
    governance: {
      jurisdiction: result.jurisdiction,
      retention: result.retention,
      exportability: result.exportability,
      consentBasis: result.consentBasis,
    },
    proof: parsed ? getFirstProof(parsed) : null,
  };
}
