import type { AnalysisContext, EvidenceSpan, Rule, RuleHit, Signal } from '../types';
import {
  CONCRETE_DESTINATIONS,
  active,
  clamp01,
  ev,
  isEducational,
  nearest,
  proximity,
  quote,
  sensitiveTargets,
} from './helpers';

/**
 * Data-exfiltration rules are correlation rules: a transmission verb alone
 * ("Explain how HTTP POST works") is not a finding. Risk comes from
 * combining:  sensitive object  +  outbound action  (+ external destination).
 */

/** Text immediately before a destination that indicates direction "to". */
const TOWARD =
  /(?:\bto|\binto|\bonto|\bat|\bvia|\btowards?|\busing|\bon|\bin|\bwith)\s+(?:\S+\s+){0,3}$/i;
const AWAY = /\bfrom\s+(?:\S+\s+){0,3}$/i;

function direction(ctx: AnalysisContext, d: Signal): 'to' | 'from' | 'unknown' {
  const segStart = ctx.segments[d.segment]?.start ?? 0;
  const before = ctx.text.slice(Math.max(segStart, d.start - 40), d.start);
  if (AWAY.test(before) && !/\bto\s+(?:\S+\s+){0,3}$/i.test(before)) return 'from';
  if (TOWARD.test(before)) return 'to';
  return 'unknown';
}

function destinationStrength(ctx: AnalysisContext, d: Signal): number {
  const base = CONCRETE_DESTINATIONS.has(d.tag) ? 0.97 : d.tag === 'external' ? 0.9 : 0.8;
  const dir = direction(ctx, d);
  if (dir === 'from') return 0; // "download from https://..." is a source, not a sink.
  return dir === 'to' ? base : base * 0.8;
}

interface Chain {
  action: Signal;
  target: Signal;
  targetDistance: number;
  destination?: { signal: Signal; strength: number; distance: number } | undefined;
}

function bestDestination(ctx: AnalysisContext, action: Signal) {
  let best: Chain['destination'];
  for (const d of ctx.signalsOf('destination')) {
    const distance = Math.abs(d.segment - action.segment);
    if (distance > 1) continue;
    const strength = destinationStrength(ctx, d) * proximity(distance);
    if (strength > 0 && (!best || strength > best.strength)) {
      best = { signal: d, strength, distance };
    }
  }
  return best;
}

function buildChains(ctx: AnalysisContext, actions: readonly Signal[]): Chain[] {
  const targets = sensitiveTargets(ctx);
  const chains: Chain[] = [];
  for (const action of active(actions)) {
    // Prefer credentials / literal secrets as the chain's object when they are
    // as close (same segment distance) as any other sensitive reference.
    const any = nearest(action, targets, 1);
    if (!any) continue;
    const credential = nearest(
      action,
      targets,
      any.distance,
      (s) => s.kind === 'secret' || s.tag === 'credential',
    );
    const near = credential ?? any;
    chains.push({
      action,
      target: near.signal,
      targetDistance: near.distance,
      destination: bestDestination(ctx, action),
    });
  }
  return chains;
}

/** Educational framing dampens, but much less when a concrete destination is given. */
function framing(ctx: AnalysisContext, chain: Chain): number {
  if (!isEducational(ctx, chain.action)) return chain.action.quoted ? 0.6 : 1;
  const concrete = chain.destination && CONCRETE_DESTINATIONS.has(chain.destination.signal.tag);
  return concrete ? 0.7 : 0.35;
}

function chainEvidence(chain: Chain): EvidenceSpan[] {
  const out = [ev(chain.action), ev(chain.target)];
  if (chain.destination) out.push(ev(chain.destination.signal));
  return out;
}

/** Keep only the strongest hit per action segment to avoid duplicate findings. */
function strongestPerSegment(hits: { segment: number; hit: RuleHit }[]): RuleHit[] {
  const best = new Map<number, RuleHit>();
  for (const { segment, hit } of hits) {
    const cur = best.get(segment);
    if (!cur || hit.confidence > cur.confidence) best.set(segment, hit);
  }
  return [...best.values()];
}

const BULK_DATA =
  /\b(?:all (?:of )?(?:the |my |our |your )?(?:data|files|information|records|results|contents|documents|messages|output|context)|everything|entire (?:\S+ )?(?:contents|database|dataset|folder|directory|drive)|full (?:contents|dump|export|dataset))\b/i;

const PLACEHOLDER_URL =
  /\b(?:https?:)?\/\/[^\s"'<>]*?(?:\{\{?\s*([^}\s]{1,40})\s*\}?\}|\$\{([^}\s]{1,40})\}|\$([A-Z_][A-Z0-9_]{1,40})|<([A-Za-z_ ]{2,30})>|\[([A-Z_]{3,30})\])/g;
const MARKDOWN_IMAGE_QUERY = /!\[[^\]\n]{0,100}\]\(\s*(?:https?:)?\/\/[^)\s]*\?[^)\s]*\)/g;
const SENSITIVE_PLACEHOLDER =
  /token|key|secret|pass|pwd|prompt|history|cookie|session|cred|auth|ssn|card|data|conversation|context|chat|email/i;

export const dataExfiltrationRules: Rule[] = [
  {
    id: 'DE-001',
    category: 'DATA_EXFILTRATION',
    title: 'Sensitive data sent to an external destination',
    description:
      'Sensitive data, an outbound transmission action and an external destination appear together.',
    severity: 'CRITICAL',
    weight: 95,
    relatedCategories: ['SENSITIVE_DATA'],
    remediation:
      'Block this prompt. Agents must not transmit credentials or confidential data to destinations supplied in prompt text. Enforce egress allow-lists and tool-level DLP.',
    patterns(ctx) {
      const hits = buildChains(ctx, ctx.signalsOf('outbound'))
        .filter((c) => c.destination)
        .map((c) => {
          const d = c.destination;
          const confidence = clamp01(
            (d?.strength ?? 0) * proximity(c.targetDistance) * framing(ctx, c),
          );
          return {
            segment: c.action.segment,
            hit: {
              confidence,
              severity: confidence >= 0.6 ? ('CRITICAL' as const) : ('MEDIUM' as const),
              explanation: `${quote(ctx, c.action)} moves ${quote(ctx, c.target)} toward ${d ? quote(ctx, d.signal) : 'an external destination'}. Sensitive data + outbound action + destination is a classic exfiltration chain.`,
              evidence: chainEvidence(c),
            },
          };
        });
      return strongestPerSegment(hits);
    },
  },
  {
    id: 'DE-002',
    category: 'DATA_EXFILTRATION',
    title: 'Sensitive data with outbound action',
    description:
      'Sensitive data is combined with a transmission action (send, upload, email, POST ...) but no explicit destination was identified.',
    severity: 'HIGH',
    weight: 65,
    relatedCategories: ['SENSITIVE_DATA'],
    remediation:
      'Confirm where the data would go. Require explicit, allow-listed destinations for any tool that transmits data, and keep credentials out of model-accessible context.',
    patterns(ctx) {
      const hits = buildChains(ctx, ctx.signalsOf('outbound'))
        .filter((c) => !c.destination)
        .map((c) => {
          const confidence = clamp01(0.8 * proximity(c.targetDistance) * framing(ctx, c));
          return {
            segment: c.action.segment,
            hit: {
              confidence,
              severity: confidence >= 0.6 ? ('HIGH' as const) : ('LOW' as const),
              explanation: `${quote(ctx, c.action)} is applied to ${quote(ctx, c.target)}.`,
              evidence: chainEvidence(c),
            },
          };
        });
      return strongestPerSegment(hits);
    },
  },
  {
    id: 'DE-003',
    category: 'DATA_EXFILTRATION',
    title: 'Sensitive data embedded in an outgoing request',
    description:
      'Sensitive data is placed into a URL, query string, header or request, which transmits it to whatever server receives the request.',
    severity: 'CRITICAL',
    weight: 90,
    relatedCategories: ['SENSITIVE_DATA'],
    remediation:
      'Never place credentials or user data in URLs, query strings or headers sent to third parties. Strip secrets from tool requests and enforce egress controls.',
    patterns(ctx) {
      const hits = buildChains(ctx, ctx.signalsOf('embed')).map((c) => {
        const confidence = clamp01(0.92 * proximity(c.targetDistance) * framing(ctx, c));
        return {
          segment: c.action.segment,
          hit: {
            confidence,
            severity: confidence >= 0.6 ? ('CRITICAL' as const) : ('LOW' as const),
            explanation: `${quote(ctx, c.target)} is embedded via ${quote(ctx, c.action)}. Any outbound request (search, fetch, image load) would carry it to an external server.`,
            evidence: chainEvidence(c),
          },
        };
      });
      return strongestPerSegment(hits);
    },
  },
  {
    id: 'DE-004',
    category: 'DATA_EXFILTRATION',
    title: 'Outbound transmission to external destination',
    description:
      'The prompt sends content to a specific external destination. No sensitive object was identified, but the transfer should be reviewed.',
    severity: 'LOW',
    weight: 28,
    remediation:
      'Verify the destination is expected and approved. Agents should only transmit to allow-listed endpoints.',
    patterns(ctx) {
      const targets = sensitiveTargets(ctx);
      const hits: { segment: number; hit: RuleHit }[] = [];
      for (const action of active(ctx.signalsOf('outbound'))) {
        if (nearest(action, targets, 1)) continue; // covered by DE-001/DE-002
        const d = bestDestination(ctx, action);
        if (!d || direction(ctx, d.signal) !== 'to') continue;
        if (isEducational(ctx, action)) continue;
        const segText = ctx.segments[action.segment]?.text ?? '';
        const bulk = BULK_DATA.test(segText);
        hits.push({
          segment: action.segment,
          hit: {
            confidence: clamp01(0.8 * d.strength),
            severity: bulk ? 'MEDIUM' : 'LOW',
            weight: bulk ? 45 : 28,
            explanation: bulk
              ? `${quote(ctx, action)} sends bulk content to ${quote(ctx, d.signal)}.`
              : `${quote(ctx, action)} sends content to ${quote(ctx, d.signal)}.`,
            evidence: [ev(action), ev(d.signal)],
          },
        });
      }
      return strongestPerSegment(hits);
    },
  },
  {
    id: 'DE-005',
    category: 'DATA_EXFILTRATION',
    title: 'Data templated into URL / markdown image',
    description:
      'A URL contains a data placeholder, or a markdown image points at a URL with a query string. Rendering such output can silently send data to the URL owner.',
    severity: 'HIGH',
    weight: 60,
    remediation:
      'Do not render model-generated images or links to arbitrary domains. Strip or allow-list URLs in model output and block templated query parameters.',
    patterns(ctx) {
      const hits: RuleHit[] = [];
      for (const m of ctx.text.matchAll(PLACEHOLDER_URL)) {
        const groups: (string | undefined)[] = m.slice(1);
        const name = groups.find((g) => g !== undefined) ?? '';
        const sensitive = SENSITIVE_PLACEHOLDER.test(name);
        hits.push({
          confidence: sensitive ? 0.9 : 0.75,
          severity: sensitive ? 'CRITICAL' : 'HIGH',
          weight: sensitive ? 85 : 60,
          explanation: `A URL contains the placeholder "${name.slice(0, 40)}", which would be filled with data and sent to the URL's server.`,
          evidence: [
            {
              start: m.index,
              end: m.index + m[0].length,
              kind: 'destination',
              label: 'URL with data placeholder (inert text)',
            },
          ],
        });
      }
      for (const m of ctx.text.matchAll(MARKDOWN_IMAGE_QUERY)) {
        hits.push({
          confidence: 0.8,
          explanation:
            'A markdown image with a query string can exfiltrate data when the output is rendered (zero-click).',
          evidence: [
            {
              start: m.index,
              end: m.index + m[0].length,
              kind: 'destination',
              label: 'Markdown image URL with query string (inert text)',
            },
          ],
        });
      }
      return hits;
    },
  },
];
