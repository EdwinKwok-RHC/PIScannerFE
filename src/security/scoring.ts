import {
  CATEGORIES,
  type Category,
  type CategoryResult,
  type Correlation,
  type Finding,
  type RiskLevel,
} from './types';

/**
 * RISK SCORING ALGORITHM
 * ======================
 *
 * The score is deterministic and runs in four steps. It deliberately does NOT
 * sum keyword hits.
 *
 * 1. Finding contribution
 *      c = weight x confidence            (0-100)
 *    `weight` is the rule's (or hit's) maximum impact. `confidence` (0..1)
 *    already includes context: educational framing, quoting, negation,
 *    clause proximity and destination concreteness.
 *
 * 2. Per-rule aggregation (diminishing repeats)
 *    Repeated hits of the same rule add little: the strongest hit counts
 *    fully and each additional hit is scaled by 0.25 before combining with
 *    a probabilistic OR:
 *      ruleScore = 100 x (1 - (1 - c1/100) x PROD(1 - 0.25 x ci/100))
 *
 * 3. Cross-rule combination (probabilistic OR)
 *      base = 100 x (1 - PROD(1 - ruleScore/100))
 *    Independent risks reinforce each other but can never exceed 100, and
 *    many weak signals cannot add up linearly to a critical score.
 *    Category scores use the same formula over rules in that category;
 *    rules with `relatedCategories` contribute to those at 0.6x.
 *
 * 4. Context correlation
 *    Combinations that indicate a real attack chain enforce score floors or
 *    add bonuses (only counting findings with confidence >= 0.6):
 *      - sensitive data + outbound action                 floor 60 (High)
 *      - sensitive data + outbound + external destination floor 85 (Critical)
 *      - prompt injection + sensitive data + transmission floor 95 (Critical)
 *      - prompt injection + sensitive-data targeting      +10
 *      - obfuscation/concealment + any transmission       +10 and floor 70
 *      - concealment + sensitive-data targeting           +8
 *    The final score is clamped to 0-100 and rounded.
 *
 * Rating bands: 0-19 Safe, 20-39 Low, 40-59 Medium, 60-79 High, 80-100 Critical.
 */

export const REPEAT_FACTOR = 0.25;
export const RELATED_CATEGORY_FACTOR = 0.6;
export const CORRELATION_MIN_CONFIDENCE = 0.6;

export function levelForScore(score: number): RiskLevel {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 20) return 'LOW';
  return 'SAFE';
}

/** Probabilistic OR of 0-100 contributions. */
export function combine(values: readonly number[]): number {
  let remaining = 1;
  for (const v of values) remaining *= 1 - Math.max(0, Math.min(100, v)) / 100;
  return 100 * (1 - remaining);
}

function ruleScores(
  findings: readonly Finding[],
): Map<string, { score: number; finding: Finding }> {
  const byRule = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byRule.get(f.ruleId) ?? [];
    list.push(f);
    byRule.set(f.ruleId, list);
  }
  const out = new Map<string, { score: number; finding: Finding }>();
  for (const [ruleId, list] of byRule) {
    const sorted = [...list].sort((a, b) => b.contribution - a.contribution);
    const [top, ...rest] = sorted;
    if (!top) continue;
    const score = combine([top.contribution, ...rest.map((f) => f.contribution * REPEAT_FACTOR)]);
    out.set(ruleId, { score, finding: top });
  }
  return out;
}

interface Flags {
  injection: boolean;
  sensitiveTargeting: boolean;
  sensitiveOutbound: boolean;
  sensitiveExternal: boolean;
  anyTransmission: boolean;
  obfuscation: boolean;
  concealment: boolean;
}

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const;

function flagsFor(findings: readonly Finding[]): Flags {
  const strong = findings.filter((f) => f.confidence >= CORRELATION_MIN_CONFIDENCE);
  const has = (pred: (f: Finding) => boolean) => strong.some(pred);
  const isRule =
    (...ids: string[]) =>
    (f: Finding) =>
      ids.includes(f.ruleId);
  return {
    injection: has((f) => f.category === 'PROMPT_INJECTION'),
    // PI-002 (system prompt extraction) is itself an injection finding, so it
    // is not counted again here to avoid double-counting one phrase.
    sensitiveTargeting: has(
      (f) =>
        (f.category === 'SENSITIVE_DATA' && SEVERITY_RANK[f.severity] >= 2) ||
        f.ruleId === 'OB-001',
    ),
    sensitiveOutbound: has(isRule('DE-001', 'DE-002', 'DE-003')),
    sensitiveExternal: has(
      (f) =>
        f.ruleId === 'DE-001' ||
        f.ruleId === 'DE-003' ||
        (f.ruleId === 'DE-005' && f.severity === 'CRITICAL'),
    ),
    anyTransmission: has((f) => f.category === 'DATA_EXFILTRATION'),
    obfuscation: has(isRule('OB-001', 'OB-004', 'OB-003')),
    concealment: has((f) => f.ruleId === 'OB-002' || f.ruleId === 'OB-003'),
  };
}

export function correlationsFor(findings: readonly Finding[]): Correlation[] {
  const f = flagsFor(findings);
  const out: Correlation[] = [];
  if (f.sensitiveOutbound) {
    out.push({
      id: 'SENSITIVE_OUTBOUND',
      description: 'Sensitive data is combined with an outbound action.',
      floor: 60,
      bonus: 0,
    });
  }
  if (f.sensitiveExternal) {
    out.push({
      id: 'SENSITIVE_OUTBOUND_DESTINATION',
      description:
        'Sensitive data, an outbound action and an external destination form a complete exfiltration chain.',
      floor: 85,
      bonus: 0,
    });
  }
  if (f.injection && f.sensitiveOutbound) {
    out.push({
      id: 'INJECTION_EXFILTRATION',
      description: 'Prompt injection is combined with sensitive data extraction and transmission.',
      floor: 95,
      bonus: 0,
    });
  } else if (f.injection && f.sensitiveTargeting) {
    out.push({
      id: 'INJECTION_SENSITIVE',
      description: 'Prompt injection is combined with targeting of sensitive data.',
      floor: 0,
      bonus: 10,
    });
  }
  if ((f.obfuscation || f.concealment) && f.anyTransmission) {
    out.push({
      id: 'OBFUSCATED_TRANSFER',
      description: 'Obfuscation or concealment is combined with data transmission.',
      floor: 70,
      bonus: 10,
    });
  } else if (f.concealment && f.sensitiveTargeting) {
    out.push({
      id: 'CONCEALED_ACCESS',
      description: 'Sensitive data access is requested covertly.',
      floor: 0,
      bonus: 8,
    });
  }
  return out;
}

function applyCorrelations(base: number, correlations: readonly Correlation[]): number {
  let score = base;
  for (const c of correlations) score += c.bonus;
  for (const c of correlations) score = Math.max(score, c.floor);
  return Math.round(Math.max(0, Math.min(100, score)));
}

/** Which correlations also raise individual category scores. */
const CATEGORY_CORRELATIONS: Record<Category, readonly string[]> = {
  DATA_EXFILTRATION: [
    'SENSITIVE_OUTBOUND',
    'SENSITIVE_OUTBOUND_DESTINATION',
    'INJECTION_EXFILTRATION',
  ],
  OBFUSCATION: ['OBFUSCATED_TRANSFER'],
  PROMPT_INJECTION: [],
  SENSITIVE_DATA: [],
};

export interface ScoreSummary {
  score: number;
  level: RiskLevel;
  categories: Record<Category, CategoryResult>;
  correlations: Correlation[];
}

export function scoreFindings(findings: readonly Finding[]): ScoreSummary {
  const rules = ruleScores(findings);
  const base = combine([...rules.values()].map((r) => r.score));
  const correlations = correlationsFor(findings);
  const score = findings.length === 0 ? 0 : applyCorrelations(base, correlations);

  const categories = {} as Record<Category, CategoryResult>;
  for (const category of CATEGORIES) {
    const parts: number[] = [];
    let count = 0;
    for (const { score: s, finding } of rules.values()) {
      if (finding.category === category) parts.push(s);
      else if (finding.relatedCategories.includes(category))
        parts.push(s * RELATED_CATEGORY_FACTOR);
    }
    for (const f of findings) if (f.category === category) count++;
    const extra = correlations.filter((c) => CATEGORY_CORRELATIONS[category].includes(c.id));
    const catBase = combine(parts);
    const catScore =
      parts.length === 0
        ? 0
        : applyCorrelations(
            catBase,
            extra.map((c) => ({ ...c, bonus: 0 })),
          );
    // Category scores never exceed the overall score.
    const bounded = Math.min(catScore, score);
    categories[category] = {
      category,
      score: bounded,
      level: levelForScore(bounded),
      findingCount: count,
    };
  }
  return { score, level: levelForScore(score), categories, correlations };
}
