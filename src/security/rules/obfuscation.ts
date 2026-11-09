import type { Rule, RuleHit, Signal } from '../types';
import {
  active,
  clamp01,
  ev,
  framingFactor,
  nearest,
  proximity,
  quote,
  sensitiveTargets,
} from './helpers';

/**
 * Obfuscation words ("Base64", "encode", "silently") are common in benign
 * engineering prompts. These rules only escalate when obfuscation is combined
 * with sensitive data access or outbound transmission.
 */

const transferSignals = (s: { kind: string }) => s.kind === 'outbound' || s.kind === 'embed';

/** Long Base64/hex runs that are not already identified as secrets. */
const ENCODED_BLOB =
  /(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{48,}={0,2}|(?:[0-9a-fA-F]{2}){32,})(?![A-Za-z0-9+/=_-])/g;

export const obfuscationRules: Rule[] = [
  {
    id: 'OB-001',
    category: 'OBFUSCATION',
    title: 'Encoding / encryption applied to sensitive data',
    description:
      'Sensitive data is encoded, encrypted or transformed, which is commonly used to slip secrets past output filters and DLP.',
    severity: 'HIGH',
    weight: 55,
    relatedCategories: ['SENSITIVE_DATA'],
    remediation:
      'Encoding is not protection. Block requests to transform credentials or confidential data, and inspect encoded content in outputs and tool calls.',
    patterns(ctx) {
      const targets = sensitiveTargets(ctx);
      const hits: RuleHit[] = [];
      const seen = new Set<number>();
      for (const o of active(ctx.signalsOf('obfuscation'))) {
        if (o.tag === 'split' || seen.has(o.segment)) continue;
        const near = nearest(o, targets, 1);
        if (!near) continue;
        seen.add(o.segment);
        const factor = framingFactor(ctx, [o]) * proximity(near.distance);
        hits.push({
          confidence: clamp01(0.85 * factor),
          severity: factor < 0.6 ? 'LOW' : 'HIGH',
          explanation:
            factor < 0.6
              ? `${quote(ctx, o)} is discussed alongside ${quote(ctx, near.signal)}, but the framing looks educational.`
              : `${quote(ctx, o)} is applied to ${quote(ctx, near.signal)}.`,
          evidence: [ev(o), ev(near.signal)],
        });
      }
      return hits;
    },
  },
  {
    id: 'OB-002',
    category: 'OBFUSCATION',
    title: 'Concealment instruction',
    description:
      'The prompt asks for the action to be performed silently or hidden from the user ("do not mention this").',
    severity: 'MEDIUM',
    weight: 30,
    remediation:
      'Legitimate tasks rarely require hiding actions from the user. Require user-visible confirmation for tool actions and log all outbound operations.',
    patterns(ctx) {
      const risky = [...sensitiveTargets(ctx), ...active(ctx.signals.filter(transferSignals))];
      const hits: RuleHit[] = [];
      for (const c of ctx.signalsOf('concealment')) {
        if (c.tag === 'evasion') continue;
        const near = nearest(c, risky, 1);
        const factor = framingFactor(ctx, [c]);
        hits.push(
          near
            ? {
                confidence: clamp01(0.85 * factor * proximity(near.distance)),
                severity: 'HIGH',
                weight: 55,
                explanation: `${quote(ctx, c)} hides an action involving ${quote(ctx, near.signal)}.`,
                evidence: [ev(c), ev(near.signal)],
              }
            : {
                confidence: clamp01(0.6 * factor),
                explanation: `${quote(ctx, c)} asks for an action to be concealed.`,
                evidence: [ev(c)],
              },
        );
      }
      return hits;
    },
  },
  {
    id: 'OB-003',
    category: 'OBFUSCATION',
    title: 'Monitoring / audit evasion',
    description:
      'The prompt asks to avoid detection, bypass monitoring, skip logging or tamper with audit trails.',
    severity: 'HIGH',
    weight: 50,
    remediation:
      'Treat any instruction to evade monitoring as malicious intent. Ensure logging and DLP run outside the model where prompts cannot disable them.',
    patterns(ctx) {
      const risky = [...sensitiveTargets(ctx), ...active(ctx.signals.filter(transferSignals))];
      return ctx
        .signalsOf('concealment')
        .filter((c) => c.tag === 'evasion')
        .map((c) => {
          const near = nearest(c, risky, 1);
          const factor = framingFactor(ctx, [c]);
          return {
            confidence: clamp01((near ? 0.9 : 0.75) * factor),
            explanation: near
              ? `${quote(ctx, c)} is combined with ${quote(ctx, near.signal)}.`
              : `${quote(ctx, c)} attempts to avoid oversight.`,
            evidence: near ? [ev(c), ev(near.signal)] : [ev(c)],
          };
        });
    },
  },
  {
    id: 'OB-004',
    category: 'OBFUSCATION',
    title: 'Data fragmentation to evade detection',
    description:
      'The prompt splits data into pieces or multiple requests, a technique used to defeat pattern-based DLP.',
    severity: 'HIGH',
    weight: 55,
    remediation:
      'Correlate tool calls across a session; fragmented transfers of sensitive data should be blocked as a whole.',
    patterns(ctx) {
      const risky = [...sensitiveTargets(ctx), ...active(ctx.signals.filter(transferSignals))];
      const hits: RuleHit[] = [];
      for (const s of active(ctx.signalsOf('obfuscation', 'split'))) {
        const near = nearest(s, risky, 1);
        if (!near) continue;
        const factor = framingFactor(ctx, [s]) * proximity(near.distance);
        hits.push({
          confidence: clamp01(0.85 * factor),
          explanation: `${quote(ctx, s)} fragments content related to ${quote(ctx, near.signal)}.`,
          evidence: [ev(s), ev(near.signal)],
        });
      }
      return hits;
    },
  },
  {
    id: 'OB-005',
    category: 'OBFUSCATION',
    title: 'Obfuscation technique requested',
    description:
      'An encoding or transformation technique is requested without an obvious sensitive target. Usually benign on its own.',
    severity: 'LOW',
    weight: 10,
    remediation:
      'No action needed unless combined with sensitive data or transmission. Review the surrounding context.',
    patterns(ctx) {
      const targets = sensitiveTargets(ctx);
      const candidates = active(ctx.signalsOf('obfuscation')).filter(
        (o: Signal) => !nearest(o, targets, 1) && framingFactor(ctx, [o]) === 1,
      );
      const first = candidates[0];
      if (!first) return [];
      return [
        {
          confidence: 0.6,
          explanation: `Mentions ${quote(ctx, first)}. Encoding alone is not risky.`,
          evidence: candidates.slice(0, 5).map((s) => ev(s)),
        },
      ];
    },
  },
  {
    id: 'OB-006',
    category: 'OBFUSCATION',
    title: 'Invisible or bidirectional control characters',
    description:
      'The prompt contains zero-width or bidi control characters that can hide instructions from human reviewers.',
    severity: 'MEDIUM',
    weight: 35,
    remediation:
      'Strip invisible Unicode characters before passing text to a model and review the visible text carefully.',
    patterns(ctx) {
      if (ctx.invisibleCharCount === 0) return [];
      return [
        {
          confidence: ctx.invisibleCharCount >= 3 ? 0.85 : 0.6,
          explanation: `Found ${ctx.invisibleCharCount} invisible character(s). They were ignored during analysis so hidden keywords could still be matched.`,
          evidence: [],
        },
      ];
    },
  },
  {
    id: 'OB-007',
    category: 'OBFUSCATION',
    title: 'Encoded payload present',
    description:
      'A long Base64 or hexadecimal string is embedded in the prompt. Encoded payloads can hide instructions or data.',
    severity: 'LOW',
    weight: 20,
    remediation:
      'Decode and review embedded payloads before use. Do not let a model decode and follow hidden instructions.',
    patterns(ctx) {
      const secrets = ctx.signalsOf('secret');
      const hits: RuleHit[] = [];
      for (const m of ctx.text.matchAll(ENCODED_BLOB)) {
        const start = m.index;
        const end = start + m[0].length;
        if (secrets.some((s) => s.start < end && start < s.end)) continue;
        if (!/[0-9]/.test(m[0]) || !/[A-Za-z]/.test(m[0])) continue;
        hits.push({
          confidence: 0.6,
          explanation: `Found a ${m[0].length}-character encoded-looking string.`,
          // Opaque payloads may contain secrets, so they are masked on display.
          evidence: [
            {
              start,
              end,
              kind: 'obfuscation',
              label: 'Encoded-looking payload (masked)',
              mask: '[ENCODED_DATA]',
            },
          ],
        });
        if (hits.length >= 3) break;
      }
      return hits;
    },
  },
];
