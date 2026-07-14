# @shieldly/iam-lint

Lightweight, static-heuristic AWS IAM policy linter. No network calls, no AWS SDK dependency —
just deterministic rules over a parsed policy document. Powered by [Shieldly](https://www.shieldly.io).

```bash
npm install @shieldly/iam-lint
```

## Usage

```js
import { lint } from '@shieldly/iam-lint';

const policy = {
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 's3:*', Resource: '*' },
  ],
};

const findings = lint(policy);
// [
//   { sev: 'high', title: 'Statement 1: Service-wide wildcard "s3:*"', detail: '...' },
//   { sev: 'medium', title: 'Statement 1: Resource "*"', detail: '...' },
// ]
```

Each finding has a `sev` (`critical` | `high` | `medium` | `info`), a `title`, a `detail`, and
an optional `link` — when present, a path relative to `https://www.shieldly.io` with more
context (e.g. `/iam/iam-passrole` explains that specific privilege-escalation path).

## CLI

The package ships an `iam-lint` command for CI and local use:

```bash
npx @shieldly/iam-lint policies/*.json
# or, installed globally:
iam-lint --fail-on medium policies/lambda-role.json
```

- Exits `1` when any finding at or above the `--fail-on` threshold is found (default: `high`).
- Files wrapped in a `PolicyDocument` key (CloudFormation-style) are unwrapped automatically.
- JSON files without a `Statement` element are skipped, so globbing broadly is safe.

## pre-commit hook

Lint IAM policies on every commit with [pre-commit](https://pre-commit.com):

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/shieldly-io/iam-lint
    rev: v1.1.0
    hooks:
      - id: iam-lint
        files: ^policies/.*\.json$   # scope to your IAM policy files (optional but faster)
```

Pass CLI flags through `args`, e.g. `args: [--fail-on, medium]`.

## What this checks

- Full wildcard actions (`Action: "*"`)
- Service-wide wildcard actions (e.g. `s3:*`)
- Privilege-escalation-capable actions (`iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, and others)
- `NotAction` combined with `Allow`
- Wildcard resources (`Resource: "*"`)
- Wildcard principals on resource-based policies (with or without a `Condition`)
- Missing `Effect`

## What this does NOT do

This applies fast, deterministic static rules — it does not reason about how permissions
combine across statements, accounts, or services, and it does not resolve variables or
evaluate conditions. For that — plus a plain-English explanation and a corrected policy —
use [Shieldly's AI-Powered analyzer](https://www.shieldly.io/app/iam). It's free to try, no
signup required for the demo.

This is the same linting logic behind the free browser tool at
[shieldly.io/tools/iam-policy-linter](https://www.shieldly.io/tools/iam-policy-linter).

## Privacy

This package runs entirely locally — it never makes a network call. Nothing you lint is sent
anywhere.

## Free tools & references (no signup)

- [IAM Privilege Escalation Cheat Sheet](https://www.shieldly.io/iam/cheatsheet?utm_source=github&utm_medium=readme) — every common escalation path on one page, with fixes
- [Free browser tools](https://www.shieldly.io/tools?utm_source=github&utm_medium=readme) — IAM policy linter, trust policy explainer, S3 bucket policy checker, CloudFormation IAM checker, ARN parser, policy diff, CloudTrail least-privilege generator, policy size calculator
- [Awesome AWS IAM Security](https://github.com/shieldly-io/awesome-aws-iam-security) — curated list of IAM security tools and references

## License

MIT
