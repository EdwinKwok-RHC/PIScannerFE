import type { EvidenceSpan, Finding, HighlightKind, HighlightRun, Span } from './types';

/** When spans overlap, the higher-priority style wins for display. */
const PRIORITY: Record<HighlightKind, number> = {
  secret: 6,
  injection: 5,
  outbound: 4,
  destination: 3,
  sensitive: 2,
  obfuscation: 1,
};

export interface Redaction extends Span {
  placeholder: string;
}

interface LabeledSpan extends EvidenceSpan {
  rule: string;
}

/**
 * Splits the ORIGINAL prompt into contiguous runs for safe rendering. Runs
 * carry plain text only; the UI renders them as React text nodes. Redacted
 * ranges (secrets, masked payloads) are replaced atomically by placeholders,
 * so the full value is never rendered.
 */
export function buildHighlights(
  original: string,
  findings: readonly Finding[],
  redactions: readonly Redaction[],
): HighlightRun[] {
  const spans: LabeledSpan[] = [];
  for (const f of findings) {
    for (const s of f.evidenceSpans) {
      if (s.end > s.start) spans.push({ ...s, rule: `${f.ruleId}: ${f.title}` });
    }
  }

  const boundaries = new Set<number>([0, original.length]);
  for (const s of spans) {
    boundaries.add(s.start);
    boundaries.add(s.end);
  }
  for (const r of redactions) {
    boundaries.add(r.start);
    boundaries.add(r.end);
  }
  const points = [...boundaries]
    .filter((p) => p >= 0 && p <= original.length)
    .sort((a, b) => a - b);

  const runs: HighlightRun[] = [];
  let i = 0;
  while (i < points.length - 1) {
    const start = points[i] ?? 0;
    let end = points[i + 1] ?? start;
    i++;
    const redaction = redactions.find((r) => r.start <= start && start < r.end);
    if (redaction) {
      // Consume every interval inside the redacted range.
      end = redaction.end;
      while (i < points.length - 1 && (points[i] ?? 0) < end) i++;
    }
    const covering = spans.filter((s) => s.start < end && start < s.end);
    let kind: HighlightKind | null = redaction ? 'secret' : null;
    for (const s of covering) {
      if (!kind || PRIORITY[s.kind] > PRIORITY[kind]) kind = s.kind;
    }
    const labels = [...new Set(covering.map((s) => `${s.label} (${s.rule})`))];
    if (redaction) labels.unshift('Credential-like value redacted');
    const text = redaction ? redaction.placeholder : original.slice(start, end);
    const prev = runs[runs.length - 1];
    if (
      prev &&
      !redaction &&
      prev.kind === kind &&
      prev.text !== '' &&
      !isPlaceholderRun(prev, redactions) &&
      sameLabels(prev.labels, labels)
    ) {
      prev.end = end;
      prev.text += text;
    } else {
      runs.push({ start, end, text, kind, labels });
    }
  }
  return runs;
}

function isPlaceholderRun(run: HighlightRun, redactions: readonly Redaction[]): boolean {
  return redactions.some((r) => r.start === run.start && r.end === run.end);
}

function sameLabels(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((v, idx) => v === b[idx]);
}
