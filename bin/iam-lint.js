#!/usr/bin/env node
/**
 * iam-lint CLI — lint AWS IAM policy JSON files from the command line.
 *
 * Usage:
 *   iam-lint [--fail-on critical|high|medium|info] <file.json> [more.json ...]
 *
 * Designed for pre-commit and CI: exits 1 when any finding at or above the
 * --fail-on threshold (default: high) is found, 0 otherwise.
 *
 * Files whose JSON has no Statement element (and no PolicyDocument.Statement)
 * are skipped — this keeps broad file matchers (e.g. pre-commit `types: [json]`)
 * safe against package.json and other non-policy JSON.
 *
 * No network calls, no AWS SDK. Powered by Shieldly (https://www.shieldly.io).
 */

import { readFileSync } from 'node:fs';
import process from 'node:process';
import { lint } from '../src/index.js';

const SEV_RANK = { info: 0, medium: 1, high: 2, critical: 3 };

function usage() {
  console.log('Usage: iam-lint [--fail-on critical|high|medium|info] <file.json> [more.json ...]');
}

const args = process.argv.slice(2);
let failOn = 'high';
const files = [];

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--help' || a === '-h') {
    usage();
    process.exit(0);
  } else if (a === '--fail-on') {
    const v = String(args[i + 1] || '').toLowerCase();
    if (!(v in SEV_RANK)) {
      console.error(
        `iam-lint: invalid --fail-on value "${args[i + 1]}" (expected critical|high|medium|info)`
      );
      process.exit(2);
    }
    failOn = v;
    i++;
  } else if (a.startsWith('-')) {
    console.error(`iam-lint: unknown option "${a}"`);
    usage();
    process.exit(2);
  } else {
    files.push(a);
  }
}

if (!files.length) {
  usage();
  process.exit(2);
}

/** Pull a policy document out of parsed JSON, unwrapping PolicyDocument if present. */
function extractPolicy(parsed) {
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    if (parsed.Statement) return parsed;
    if (parsed.PolicyDocument?.Statement) return parsed.PolicyDocument;
  }
  return null;
}

let failing = 0;
let parseErrors = 0;

for (const file of files) {
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch (err) {
    console.error(`${file}: cannot read file (${err.message})`);
    parseErrors++;
    continue;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.error(`${file}: invalid JSON (${err.message})`);
    parseErrors++;
    continue;
  }

  const policy = extractPolicy(parsed);
  if (!policy) continue; // not an IAM policy document — skip silently

  const findings = lint(policy);
  const flagged = findings.filter((f) => SEV_RANK[f.sev] >= SEV_RANK[failOn]);
  if (!findings.length) continue;

  console.log(`\n${file}`);
  for (const f of findings) {
    const marker = SEV_RANK[f.sev] >= SEV_RANK[failOn] ? '✖' : '·';
    console.log(`  ${marker} [${f.sev}] ${f.title}`);
    console.log(`      ${f.detail}`);
    if (f.link) console.log(`      https://www.shieldly.io${f.link}`);
  }
  failing += flagged.length;
}

if (failing || parseErrors) {
  console.log(
    `\niam-lint: ${failing} finding(s) at or above "${failOn}"${parseErrors ? `, ${parseErrors} unreadable file(s)` : ''}.`
  );
  console.log('Deeper AI-Powered analysis (free, no signup): https://www.shieldly.io/app/iam');
  process.exit(1);
}
process.exit(0);
