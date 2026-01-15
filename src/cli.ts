#!/usr/bin/env node
/**
 * ddna - Command line interface for .ddna signing tools
 *
 * Commands:
 *   seal    - Seal an EDM artifact into a .ddna envelope
 *   verify  - Verify a .ddna envelope signature
 *   inspect - Inspect a .ddna envelope
 *   keygen  - Generate Ed25519 key pair
 */

import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { seal } from './lib/seal.js';
import { verify } from './lib/verify.js';
import { inspect, inspectJson } from './lib/inspect.js';
import { keygen, keyToHex, hexToKey } from './lib/keygen.js';

// Get package version
const __dirname = path.dirname(fileURLToPath(import.meta.url));
let version = '0.1.0';
try {
  const pkgPath = path.resolve(__dirname, '..', 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
  version = pkg.version;
} catch {
  // Use default version
}

const program = new Command();

program
  .name('ddna')
  .description('Command line tools for .ddna signing specification')
  .version(version);

/**
 * Read file and parse as JSON
 */
function readJsonFile(filePath: string): object {
  const absolutePath = path.resolve(filePath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const content = fs.readFileSync(absolutePath, 'utf-8');

  try {
    return JSON.parse(content);
  } catch (error) {
    throw new Error(`Invalid JSON in ${filePath}: ${error instanceof Error ? error.message : error}`);
  }
}

/**
 * Read private key from file
 */
function readPrivateKey(keyPath: string): Uint8Array {
  const absolutePath = path.resolve(keyPath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Key file not found: ${keyPath}`);
  }

  const content = fs.readFileSync(absolutePath, 'utf-8').trim();

  // Support hex-encoded keys
  try {
    return hexToKey(content);
  } catch {
    throw new Error(`Invalid key format in ${keyPath}: expected 32-byte hex-encoded private key`);
  }
}

/**
 * Generate output filename
 */
function getOutputPath(inputPath: string, extension: string): string {
  const dir = path.dirname(inputPath);
  const basename = path.basename(inputPath);

  // Remove existing extensions like .edm.json, .json
  let name = basename;
  if (name.endsWith('.edm.json')) {
    name = name.slice(0, -9);
  } else if (name.endsWith('.json')) {
    name = name.slice(0, -5);
  }

  return path.join(dir, `${name}${extension}`);
}

// ============================================================================
// SEAL COMMAND
// ============================================================================

program
  .command('seal')
  .description('Seal an EDM artifact into a .ddna envelope')
  .argument('<input>', 'Path to EDM artifact (.edm.json or .json)')
  .requiredOption('-k, --key <path>', 'Path to private key file (hex-encoded)')
  .requiredOption('-d, --did <url>', 'DID URL for verification method')
  .option('-o, --output <path>', 'Output path (default: <input>.ddna)')
  .option('--jurisdiction <code>', 'Override jurisdiction code (e.g., AU, US)')
  .option('--expires <iso8601>', 'Proof expiration timestamp')
  .action(async (input: string, options) => {
    try {
      // Read input file
      const edmPayload = readJsonFile(input);

      // Read private key
      const privateKey = readPrivateKey(options.key);

      // Seal the envelope
      const envelope = await seal(edmPayload, privateKey, options.did, {
        header: options.jurisdiction ? { jurisdiction: options.jurisdiction } : undefined,
        expires: options.expires,
      });

      // Determine output path
      const outputPath = options.output || getOutputPath(input, '.ddna');

      // Write output
      fs.writeFileSync(outputPath, JSON.stringify(envelope, null, 2));

      console.log(chalk.green('✓') + ' Sealed envelope written to: ' + chalk.cyan(outputPath));
      console.log('  Signed by: ' + chalk.dim(options.did.slice(0, 40) + '...'));
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// VERIFY COMMAND
// ============================================================================

program
  .command('verify')
  .description('Verify a .ddna envelope signature')
  .argument('<input>', 'Path to .ddna envelope')
  .option('--skip-timestamp', 'Skip timestamp validation')
  .action(async (input: string, options) => {
    try {
      // Read envelope
      const envelope = readJsonFile(input);

      // Verify
      const result = await verify(envelope, {
        skipTimestampCheck: options.skipTimestamp,
      });

      if (result.valid) {
        console.log(chalk.green('VALID') + ' - Signature verified');
        console.log('  Verification Method: ' + chalk.dim(result.verificationMethod));
        console.log('  Created: ' + chalk.dim(result.created));
      } else {
        console.log(chalk.red('INVALID') + ' - ' + result.reason);
        if (result.verificationMethod) {
          console.log('  Verification Method: ' + chalk.dim(result.verificationMethod));
        }
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// INSPECT COMMAND
// ============================================================================

program
  .command('inspect')
  .description('Inspect a .ddna envelope')
  .argument('<input>', 'Path to .ddna envelope')
  .option('--json', 'Output as JSON')
  .action(async (input: string, options) => {
    try {
      // Read envelope
      const envelope = readJsonFile(input);

      if (options.json) {
        // JSON output
        const result = await inspectJson(envelope);
        console.log(JSON.stringify(result, null, 2));
      } else {
        // Human-readable output
        const output = await inspect(envelope);
        console.log(output);
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// KEYGEN COMMAND
// ============================================================================

program
  .command('keygen')
  .description('Generate Ed25519 key pair in DID format')
  .option('-o, --output <prefix>', 'Output file prefix (creates <prefix>.key and <prefix>.pub)')
  .option('--json', 'Output as JSON to stdout')
  .action((options) => {
    try {
      // Generate key pair
      const keys = keygen();

      if (options.json) {
        // JSON output to stdout
        console.log(
          JSON.stringify(
            {
              did: keys.did,
              privateKey: keyToHex(keys.privateKey),
              publicKey: keyToHex(keys.publicKey),
            },
            null,
            2
          )
        );
      } else if (options.output) {
        // Write to files
        const keyPath = `${options.output}.key`;
        const pubPath = `${options.output}.pub`;

        fs.writeFileSync(keyPath, keyToHex(keys.privateKey));
        fs.writeFileSync(pubPath, keyToHex(keys.publicKey));

        console.log(chalk.green('✓') + ' Key pair generated');
        console.log('  Private key: ' + chalk.cyan(keyPath));
        console.log('  Public key:  ' + chalk.cyan(pubPath));
        console.log('  DID:         ' + chalk.yellow(keys.did));
      } else {
        // Output to stdout
        console.log(chalk.bold('Generated Ed25519 Key Pair'));
        console.log('');
        console.log(chalk.cyan('DID:'));
        console.log('  ' + keys.did);
        console.log('');
        console.log(chalk.cyan('Private Key (hex):'));
        console.log('  ' + keyToHex(keys.privateKey));
        console.log('');
        console.log(chalk.cyan('Public Key (hex):'));
        console.log('  ' + keyToHex(keys.publicKey));
        console.log('');
        console.log(chalk.dim('Use --output <prefix> to save to files'));
      }
    } catch (error) {
      console.error(chalk.red('Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ============================================================================
// PARSE AND EXECUTE
// ============================================================================

program.parse();
