import type { Category, Rule, RuleHit, Severity } from '../types';
import { active, ev, framingFactor, quote } from './helpers';

interface InjectionRuleSpec {
  id: string;
  tags: readonly string[];
  title: string;
  description: string;
  severity: Severity;
  weight: number;
  remediation: string;
  relatedCategories?: readonly Category[];
}

/**
 * Injection signals are already contextual phrases (verb + target), so each
 * non-negated occurrence is a hit. Negated phrasing ("never reveal your
 * system prompt") is typical of defensive system prompts and is skipped.
 */
function injectionRule(spec: InjectionRuleSpec): Rule {
  return {
    id: spec.id,
    category: 'PROMPT_INJECTION',
    title: spec.title,
    description: spec.description,
    severity: spec.severity,
    weight: spec.weight,
    remediation: spec.remediation,
    ...(spec.relatedCategories ? { relatedCategories: spec.relatedCategories } : {}),
    patterns(ctx) {
      const hits: RuleHit[] = [];
      const signals = active(ctx.signalsOf('injection')).filter((s) => spec.tags.includes(s.tag));
      for (const s of signals) {
        const factor = framingFactor(ctx, [s]);
        hits.push({
          confidence: 0.9 * factor,
          explanation:
            factor < 1
              ? `Found ${quote(ctx, s)}. The surrounding text appears educational or quoted, so confidence is reduced.`
              : `Found ${quote(ctx, s)}. ${spec.description}`,
          evidence: [ev(s)],
        });
      }
      return hits;
    },
  };
}

export const promptInjectionRules: Rule[] = [
  injectionRule({
    id: 'PI-001',
    tags: ['override'],
    title: 'Instruction override attempt',
    description:
      'The prompt tries to make the model ignore, disregard or override earlier/system instructions.',
    severity: 'HIGH',
    weight: 55,
    remediation:
      'Treat this input as untrusted. Keep system instructions isolated from user/content channels, and never let user-supplied text redefine model behavior.',
  }),
  injectionRule({
    id: 'PI-002',
    tags: ['reveal'],
    title: 'System prompt / hidden instruction extraction',
    description:
      'The prompt asks the model to reveal its system prompt, developer instructions or other hidden context.',
    severity: 'HIGH',
    weight: 55,
    relatedCategories: ['SENSITIVE_DATA'],
    remediation:
      'Do not place secrets in system prompts. Add output filtering for system-prompt leakage and refuse requests to disclose hidden instructions.',
  }),
  injectionRule({
    id: 'PI-003',
    tags: ['bypass'],
    title: 'Safeguard bypass request',
    description: 'The prompt asks to bypass, disable or remove safety restrictions or filters.',
    severity: 'HIGH',
    weight: 50,
    remediation:
      'Reject attempts to disable safeguards. Enforce safety controls outside the model so they cannot be switched off by prompt text.',
  }),
  injectionRule({
    id: 'PI-004',
    tags: ['jailbreak'],
    title: 'Jailbreak / unrestricted mode',
    description:
      'The prompt uses well-known jailbreak framing such as "developer mode" or "do anything now".',
    severity: 'MEDIUM',
    weight: 45,
    remediation:
      'Block or flag known jailbreak personas. Do not rely on the model alone to resist role-play based bypasses.',
  }),
  injectionRule({
    id: 'PI-005',
    tags: ['roleplay'],
    title: 'Restriction-free role-play',
    description: 'The prompt asks the model to pretend it has no rules or restrictions.',
    severity: 'MEDIUM',
    weight: 40,
    remediation:
      'Treat "pretend you have no restrictions" framing as an injection attempt and keep policy enforcement independent of the conversation.',
  }),
  injectionRule({
    id: 'PI-006',
    tags: ['indirect'],
    title: 'Indirect injection: obey external content',
    description:
      'The prompt tells the model to follow instructions found in web pages, documents, emails or tool output.',
    severity: 'HIGH',
    weight: 50,
    remediation:
      'Treat retrieved content and tool output as data, never as instructions. Delimit external content and instruct the model not to execute embedded commands.',
  }),
];
