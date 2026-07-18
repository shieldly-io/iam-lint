/**
 * @shieldly/iam-lint — lightweight, static-heuristic IAM policy linter.
 *
 * No network calls, no AWS SDK dependency. Flags obvious structural risks
 * (wildcard actions/resources, privilege-escalation-capable actions, public
 * principals, NotAction+Allow) using deterministic rules — the same
 * heuristics as the free browser tool at https://www.shieldly.io/tools/iam-policy-linter.
 *
 * This does NOT reason about how permissions interact across statements,
 * accounts, or services. For that, see Shieldly's AI-Powered analyzer
 * (https://www.shieldly.io/app/iam) — free to try, no signup for the demo.
 */

// Dangerous actions that enable privilege escalation, mapped to the matching
// shieldly.io reference page for a deep explanation of the attack path.
const ESCALATION_ACTIONS = {
  'iam:createpolicyversion': 'iam-createpolicyversion',
  'iam:setdefaultpolicyversion': 'iam-setdefaultpolicyversion',
  'iam:attachuserpolicy': 'iam-attachuserpolicy',
  'iam:attachrolepolicy': 'iam-attachuserpolicy',
  'iam:attachgrouppolicy': 'iam-attachuserpolicy',
  'iam:putuserpolicy': 'iam-putuserpolicy',
  'iam:putrolepolicy': 'iam-putuserpolicy',
  'iam:putgrouppolicy': 'iam-putuserpolicy',
  'iam:addusertogroup': 'iam-addusertogroup',
  'iam:createaccesskey': 'iam-createaccesskey',
  'iam:createloginprofile': 'iam-createloginprofile',
  'iam:updateloginprofile': 'iam-createloginprofile',
  'iam:updateassumerolepolicy': 'iam-updateassumerolepolicy',
  'iam:passrole': 'passrole-lambda',
};

function toArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/**
 * Run static heuristics over a parsed IAM policy document.
 * @param {object} policy - Parsed IAM policy JSON (already JSON.parse'd).
 * @returns {Array<{sev: 'critical'|'high'|'medium'|'info', title: string, detail: string, link?: string}>}
 *   `link`, when present, is a path relative to https://www.shieldly.io.
 */
export function lint(policy) {
  const findings = [];
  const statements = toArray(policy.Statement);
  if (!statements.length) {
    findings.push({
      sev: 'info',
      title: 'No Statement array found',
      detail: 'A valid IAM policy needs a Statement element with at least one statement.',
    });
    return findings;
  }

  statements.forEach((st, idx) => {
    const where = `Statement ${idx + 1}`;
    const effect = st.Effect || '(missing Effect)';
    const isAllow = effect === 'Allow';
    const actions = toArray(st.Action).map((a) => String(a));
    const notActions = toArray(st.NotAction).map((a) => String(a));
    const resources = toArray(st.Resource).map((r) => String(r));
    const principals = st.Principal;
    const hasCondition = st.Condition && Object.keys(st.Condition).length > 0;

    if (isAllow && actions.includes('*')) {
      findings.push({
        sev: 'critical',
        title: `${where}: Allow on every action ("Action": "*")`,
        detail:
          'This grants every AWS action. Combined with a broad Resource it is administrator access.',
      });
    }

    for (const a of actions) {
      if (a !== '*' && a.endsWith(':*')) {
        findings.push({
          sev: 'high',
          title: `${where}: Service-wide wildcard "${a}"`,
          detail: `Grants every action in ${a.split(':')[0]}. Scope to the specific actions you need.`,
        });
      }
    }

    for (const a of actions) {
      const key = a.toLowerCase();
      if (isAllow && ESCALATION_ACTIONS[key]) {
        findings.push({
          sev: 'high',
          title: `${where}: Privilege-escalation action "${a}"`,
          detail: 'This action can be abused to gain more permissions if not tightly scoped.',
          link: `/iam/${ESCALATION_ACTIONS[key]}`,
        });
      }
      if (isAllow && key === 'iam:*') {
        findings.push({
          sev: 'critical',
          title: `${where}: Full IAM control ("iam:*")`,
          detail: 'Full IAM access lets the principal grant itself anything. Treat as admin.',
        });
      }
    }

    if (isAllow && notActions.length) {
      findings.push({
        sev: 'high',
        title: `${where}: Allow + NotAction`,
        detail:
          'NotAction with Allow permits every action you did NOT list — usually far broader than intended.',
        link: '/blog/aws-iam-notaction-vs-deny',
      });
    }

    if (isAllow && resources.includes('*')) {
      findings.push({
        sev: 'medium',
        title: `${where}: Resource "*"`,
        detail: 'Applies to every resource. Replace with specific ARNs where possible.',
      });
    }

    if (isAllow && principals !== undefined) {
      const principalStr = JSON.stringify(principals);
      if (principalStr.includes('"*"') || principals === '*') {
        findings.push({
          sev: hasCondition ? 'medium' : 'critical',
          title: `${where}: Principal "*"${hasCondition ? ' (with condition)' : ''}`,
          detail: hasCondition
            ? 'A wildcard principal is constrained by your Condition — verify the condition is tight.'
            : 'A wildcard principal with no Condition makes this resource public.',
          link: '/iam/glossary/resource-based-policy',
        });
      }
    }

    if (effect === '(missing Effect)') {
      findings.push({
        sev: 'info',
        title: `${where}: missing Effect`,
        detail: 'Each statement needs an Effect of Allow or Deny.',
      });
    }
  });

  return findings;
}

export default lint;
