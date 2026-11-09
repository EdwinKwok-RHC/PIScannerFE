import type { AnalysisContext, EvidenceSpan, HighlightKind, Signal, SignalKind } from '../types';

/** Maps low-level signal kinds onto the five UI highlight styles. */
export const HIGHLIGHT_FOR: Record<SignalKind, HighlightKind> = {
  injection: 'injection',
  outbound: 'outbound',
  embed: 'outbound',
  destination: 'destination',
  sensitive: 'sensitive',
  secret: 'secret',
  access: 'sensitive',
  obfuscation: 'obfuscation',
  concealment: 'obfuscation',
};

export function ev(signal: Signal, label = signal.label): EvidenceSpan {
  return { start: signal.start, end: signal.end, kind: HIGHLIGHT_FOR[signal.kind], label };
}

/** Destination tags that name a concrete, addressable target. */
export const CONCRETE_DESTINATIONS = new Set([
  'url',
  'email',
  'ip',
  'domain',
  'webhook',
  'storage',
]);

/**
 * Contextual dampening.
 *  - Educational / descriptive framing ("Explain...", "for example") x0.4
 *  - Quoted text (likely an example being discussed) x0.6
 * Factors multiply, so a quoted example inside an explanation is x0.24.
 */
export function framingFactor(ctx: AnalysisContext, signals: readonly Signal[]): number {
  let factor = 1;
  const segs = new Set(signals.map((s) => s.segment));
  const educational = [...segs].some((i) => ctx.segments[i]?.educational === true);
  if (educational) factor *= 0.4;
  if (signals.length > 0 && signals.every((s) => s.quoted)) factor *= 0.6;
  return factor;
}

export function isEducational(ctx: AnalysisContext, signal: Signal): boolean {
  return ctx.segments[signal.segment]?.educational === true;
}

/** Proximity factor by segment distance: same clause 1.0, adjacent 0.85. */
export function proximity(distance: number): number {
  if (distance <= 0) return 1;
  if (distance === 1) return 0.85;
  return 0.6;
}

export interface Near {
  signal: Signal;
  distance: number;
}

/**
 * Finds the closest candidate to `from` within `maxSegments` segments,
 * preferring the same segment and then the smallest character gap.
 */
export function nearest(
  from: Signal,
  candidates: readonly Signal[],
  maxSegments = 1,
  accept: (s: Signal) => boolean = () => true,
): Near | undefined {
  let best: Near | undefined;
  let bestGap = Infinity;
  for (const c of candidates) {
    if (c === from || !accept(c)) continue;
    const distance = Math.abs(c.segment - from.segment);
    if (distance > maxSegments) continue;
    const gap = c.start >= from.end ? c.start - from.end : from.start - c.end;
    if (
      !best ||
      distance < best.distance ||
      (distance === best.distance && Math.abs(gap) < bestGap)
    ) {
      best = { signal: c, distance };
      bestGap = Math.abs(gap);
    }
  }
  return best;
}

export const active = (signals: readonly Signal[]): Signal[] => signals.filter((s) => !s.negated);

/** Sensitive objects, including literal secret values. */
export function sensitiveTargets(ctx: AnalysisContext): Signal[] {
  return active([...ctx.signalsOf('sensitive'), ...ctx.signalsOf('secret')]);
}

/** Groups signals by segment so a rule produces at most one hit per clause. */
export function bySegment(signals: readonly Signal[]): Map<number, Signal[]> {
  const map = new Map<number, Signal[]>();
  for (const s of signals) {
    const list = map.get(s.segment) ?? [];
    list.push(s);
    map.set(s.segment, list);
  }
  return map;
}

export function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

/**
 * Short quotation of a signal for explanations. Literal secrets are never
 * quoted (the engine additionally redacts all explanation text).
 */
export function quote(ctx: AnalysisContext, s: Signal): string {
  if (s.kind === 'secret') return 'a credential-like value';
  return `"${ctx.text.slice(s.start, s.end).replace(/\s+/g, ' ').slice(0, 60)}"`;
}
