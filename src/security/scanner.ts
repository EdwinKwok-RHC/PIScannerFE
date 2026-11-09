import { buildHighlights, type Redaction } from './highlights';
import { normalizeText, toNormalizedSpan, toOriginalSpan } from './normalize';
import { findSecrets, redactRange, redactSecrets } from './redaction';
import { RULES } from './rules';
import { scoreFindings } from './scoring';
import { extractSignals, segmentText } from './signals';
import type {
  AnalysisContext,
  ConfidenceLabel,
  EvidenceSpan,
  Finding,
  Rule,
  ScanOptions,
  ScanResult,
  Signal,
  SignalKind,
  Span,
} from './types';

/** Hard upper bound for analysis regardless of UI configuration. */
export const MAX_SUPPORTED_LENGTH = 100_000;
const MAX_EVIDENCE_CHARS = 240;
const MIN_CONFIDENCE = 0.05;
const MAX_HITS_PER_RULE = 5;

export function confidenceLabel(confidence: number): ConfidenceLabel {
  if (confidence >= 0.8) return 'High';
  if (confidence >= 0.55) return 'Medium';
  return 'Low';
}

/** Builds the analysis context (normalization, segmentation, signals). */
export function buildContext(original: string): {
  ctx: AnalysisContext;
  toOriginal: (span: Span) => Span;
  secrets: ReturnType<typeof findSecrets>;
} {
  const secrets = findSecrets(original);
  const norm = normalizeText(original);
  const segments = segmentText(norm.text);
  const signals: Signal[] = extractSignals(norm.text, segments);

  // Literal secrets become signals so they participate in correlation.
  for (const s of secrets) {
    const span = toNormalizedSpan(norm, s.start, s.end);
    const segIdx = Math.max(
      0,
      segments.findIndex((seg) => seg.start <= span.start && span.start < seg.end),
    );
    signals.push({
      kind: 'secret',
      tag: s.type,
      label: `Credential-like value (${s.type}), redacted`,
      start: span.start,
      end: span.end,
      segment: segIdx,
      negated: false,
      quoted: false,
    });
  }
  signals.sort((a, b) => a.start - b.start);

  const ctx: AnalysisContext = {
    text: norm.text,
    segments,
    signals,
    invisibleCharCount: norm.invisibleCharCount,
    signalsOf(kind: SignalKind, tag?: string) {
      return signals.filter((s) => s.kind === kind && (tag === undefined || s.tag === tag));
    },
    segmentOf(span: Span) {
      return (
        segments.find((seg) => seg.start <= span.start && span.start < seg.end) ??
        segments[segments.length - 1] ?? {
          index: 0,
          start: 0,
          end: 0,
          text: '',
          educational: false,
        }
      );
    },
  };
  const toOriginal = (span: Span) => toOriginalSpan(norm, span.start, span.end, original);
  return { ctx, toOriginal, secrets };
}

function evidenceText(
  original: string,
  spans: readonly Span[],
  redactions: readonly Redaction[],
): string {
  if (spans.length === 0) return '';
  const sorted = [...spans].sort((a, b) => a.start - b.start);
  const first = sorted[0];
  const minStart = first?.start ?? 0;
  const maxEnd = Math.max(...sorted.map((s) => s.end));
  const secretsLike = redactions.map((r) => ({ ...r, type: 'SECRET' as const }));
  let text: string;
  if (maxEnd - minStart <= MAX_EVIDENCE_CHARS) {
    text = redactRange(original, { start: minStart, end: maxEnd }, secretsLike);
  } else {
    // Merge overlapping spans and join with an ellipsis.
    const merged: Span[] = [];
    for (const s of sorted) {
      const last = merged[merged.length - 1];
      if (last && s.start <= last.end) last.end = Math.max(last.end, s.end);
      else merged.push({ ...s });
    }
    text = merged.map((s) => redactRange(original, s, secretsLike)).join(' … ');
  }
  text = text.replace(/\s+/g, ' ').trim();
  if (text.length > MAX_EVIDENCE_CHARS) text = `${text.slice(0, MAX_EVIDENCE_CHARS - 1)}…`;
  // Defense in depth: re-run secret detection on the final string.
  return redactSecrets(text);
}

function runRule(rule: Rule, ctx: AnalysisContext) {
  return rule
    .patterns(ctx)
    .filter((h) => h.confidence >= MIN_CONFIDENCE)
    .sort(
      (a, b) => b.confidence * (b.weight ?? rule.weight) - a.confidence * (a.weight ?? rule.weight),
    )
    .slice(0, MAX_HITS_PER_RULE);
}

/**
 * Scans a prompt with every registered rule and returns a structured,
 * fully redacted result. Pure and synchronous: no I/O, no network, no
 * storage. Safe to call from UI, tests or any other JavaScript runtime.
 */
export function scanPrompt(
  prompt: string,
  options: ScanOptions = {},
  rules: readonly Rule[] = RULES,
): ScanResult {
  const limit = Math.min(options.maxLength ?? MAX_SUPPORTED_LENGTH, MAX_SUPPORTED_LENGTH);
  const input = typeof prompt === 'string' ? prompt : '';
  const truncated = input.length > limit;
  const original = truncated ? input.slice(0, limit) : input;

  if (original.trim().length === 0) {
    const empty = scoreFindings([]);
    return {
      ...empty,
      findings: [],
      highlights: original
        ? [{ start: 0, end: original.length, text: original, kind: null, labels: [] }]
        : [],
      secretsRedacted: 0,
      inputLength: input.length,
      truncated,
    };
  }

  const { ctx, toOriginal, secrets } = buildContext(original);

  // First pass: collect hits with original-space evidence and masks.
  const raw: { rule: Rule; hit: ReturnType<Rule['patterns']>[number]; spans: EvidenceSpan[] }[] =
    [];
  const redactions: Redaction[] = secrets.map((s) => ({
    start: s.start,
    end: s.end,
    placeholder: s.placeholder,
  }));
  for (const rule of rules) {
    for (const hit of runRule(rule, ctx)) {
      const spans = hit.evidence.map((e) => ({ ...e, ...toOriginal(e) }));
      for (const s of spans) {
        if (s.mask && !redactions.some((r) => r.start < s.end && s.start < r.end)) {
          redactions.push({ start: s.start, end: s.end, placeholder: s.mask });
        }
      }
      raw.push({ rule, hit, spans });
    }
  }
  redactions.sort((a, b) => a.start - b.start);

  const findings: Finding[] = raw.map(({ rule, hit, spans }, idx) => {
    const weight = hit.weight ?? rule.weight;
    return {
      id: `${rule.id}-${idx + 1}`,
      ruleId: rule.id,
      category: rule.category,
      relatedCategories: rule.relatedCategories ?? [],
      severity: hit.severity ?? rule.severity,
      confidence: Math.round(hit.confidence * 100) / 100,
      confidenceLabel: confidenceLabel(hit.confidence),
      title: rule.title,
      description: rule.description,
      explanation: redactSecrets(hit.explanation),
      evidence: evidenceText(original, spans, redactions),
      evidenceSpans: spans,
      remediation: rule.remediation,
      contribution: Math.round(weight * hit.confidence * 10) / 10,
    };
  });

  findings.sort((a, b) => b.contribution - a.contribution);
  const summary = scoreFindings(findings);

  return {
    ...summary,
    findings,
    highlights: buildHighlights(original, findings, redactions),
    secretsRedacted: secrets.length,
    inputLength: input.length,
    truncated,
  };
}
