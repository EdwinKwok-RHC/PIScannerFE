import type { AnalysisContext, Rule, RuleHit, Severity, Signal } from '../types';
import { active, bySegment, ev, framingFactor, quote } from './helpers';

/** Verbs that indicate the prompt is *targeting* the data, not just naming it. */
function targetingVerb(ctx: AnalysisContext, target: Signal): Signal | undefined {
  const verbs = active([
    ...ctx.signalsOf('access'),
    ...ctx.signalsOf('outbound'),
    ...ctx.signalsOf('embed'),
    ...ctx.signalsOf('obfuscation'),
  ]);
  // A verb in the same clause, before the object and reasonably close
  // ("read the API key", "dump all customer records").
  return verbs.find(
    (v) =>
      v.segment === target.segment &&
      v.start < target.start &&
      target.start - v.end <= 80 &&
      !(v.start >= target.start && v.end <= target.end),
  );
}

interface SensitiveRuleSpec {
  id: string;
  tags: readonly string[];
  title: string;
  description: string;
  /** Severity/weight when the data is actively targeted. */
  targeted: { severity: Severity; weight: number };
  /** Severity/weight when the data is merely referenced. */
  reference: { severity: Severity; weight: number };
  remediation: string;
  /** Skip signals already covered by an injection signal (avoids double counting). */
  skipInsideInjection?: boolean;
}

function sensitiveRule(spec: SensitiveRuleSpec): Rule {
  return {
    id: spec.id,
    category: 'SENSITIVE_DATA',
    title: spec.title,
    description: spec.description,
    severity: spec.targeted.severity,
    weight: spec.targeted.weight,
    remediation: spec.remediation,
    patterns(ctx) {
      const injections = ctx.signalsOf('injection');
      const targets = active(ctx.signalsOf('sensitive')).filter(
        (s) =>
          spec.tags.includes(s.tag) &&
          !(
            spec.skipInsideInjection && injections.some((i) => i.start <= s.start && s.end <= i.end)
          ),
      );
      const hits: RuleHit[] = [];
      // One hit per clause keeps repeated mentions from inflating the score.
      for (const [, group] of bySegment(targets)) {
        const targeted = group
          .map((s) => ({ s, verb: targetingVerb(ctx, s) }))
          .filter((x): x is { s: Signal; verb: Signal } => x.verb !== undefined);
        const factor = framingFactor(ctx, group);
        if (targeted.length > 0) {
          const first = targeted[0];
          if (!first) continue;
          hits.push({
            confidence: 0.8 * factor,
            severity: factor < 1 ? 'LOW' : spec.targeted.severity,
            weight: spec.targeted.weight,
            explanation: `The prompt targets ${quote(ctx, first.s)} with the action ${quote(ctx, first.verb)}. ${spec.description}`,
            evidence: [
              ev(first.verb, 'Action targeting sensitive data'),
              ...group.map((s) => ev(s)),
            ],
          });
        } else {
          const first = group[0];
          if (!first) continue;
          hits.push({
            confidence: 0.6 * factor,
            severity: spec.reference.severity,
            weight: spec.reference.weight,
            explanation: `References ${quote(ctx, first)} without a clear instruction to access or move it.`,
            evidence: group.map((s) => ev(s)),
          });
        }
      }
      return hits;
    },
  };
}

export const sensitiveDataRules: Rule[] = [
  sensitiveRule({
    id: 'SD-001',
    tags: ['credential'],
    title: 'Credential / secret targeting',
    description:
      'API keys, tokens, passwords, private keys and similar credentials are referenced.',
    targeted: { severity: 'MEDIUM', weight: 40 },
    reference: { severity: 'LOW', weight: 12 },
    remediation:
      'Never give a model direct access to credentials. Use managed identities or a broker that keeps secrets out of model context, and scope tokens to least privilege.',
  }),
  sensitiveRule({
    id: 'SD-002',
    tags: ['environment'],
    title: 'Environment / secret store access',
    description:
      'The prompt references environment variables, .env files, key vaults or credential files.',
    targeted: { severity: 'HIGH', weight: 50 },
    reference: { severity: 'LOW', weight: 15 },
    remediation:
      'Agents and tools should not be able to read process environment or secret stores on behalf of prompt content. Restrict tool permissions.',
  }),
  sensitiveRule({
    id: 'SD-003',
    tags: ['conversation', 'prompt'],
    title: 'Conversation history / hidden context targeting',
    description:
      'The prompt targets conversation history, system/developer prompts or other hidden model context.',
    targeted: { severity: 'MEDIUM', weight: 35 },
    reference: { severity: 'LOW', weight: 10 },
    skipInsideInjection: true,
    remediation:
      'Treat conversation history and system prompts as confidential. Do not allow tools to export model context.',
  }),
  sensitiveRule({
    id: 'SD-004',
    tags: ['pii', 'financial', 'health'],
    title: 'Regulated personal, financial or health data',
    description: 'The prompt references PII, customer records, financial or health information.',
    targeted: { severity: 'MEDIUM', weight: 35 },
    reference: { severity: 'LOW', weight: 10 },
    remediation:
      'Minimize regulated data in prompts. Apply data classification, masking and DLP controls before data reaches a model or tool.',
  }),
  sensitiveRule({
    id: 'SD-005',
    tags: ['proprietary'],
    title: 'Proprietary code / internal documents',
    description:
      'The prompt references proprietary source code or internal/confidential documents.',
    targeted: { severity: 'MEDIUM', weight: 30 },
    reference: { severity: 'LOW', weight: 10 },
    remediation:
      'Confirm the model and any connected tools are approved for confidential material and that outputs cannot leave the trust boundary.',
  }),
  {
    id: 'SD-006',
    category: 'SENSITIVE_DATA',
    title: 'Credential-like value present in prompt',
    description:
      'The prompt contains a literal value that matches a known credential format. It has been redacted from all results.',
    severity: 'HIGH',
    weight: 50,
    remediation:
      'Remove the secret from the prompt and rotate it: anything pasted into an AI system may be logged or retained.',
    patterns(ctx) {
      const secrets = ctx.signalsOf('secret');
      if (secrets.length === 0) return [];
      const types = [...new Set(secrets.map((s) => s.tag))].join(', ');
      return [
        {
          confidence: 0.95,
          explanation: `Detected ${secrets.length} credential-like value(s) (${types}). Values are redacted and never displayed.`,
          evidence: secrets.map((s) => ev(s)),
        },
      ];
    },
  },
];
