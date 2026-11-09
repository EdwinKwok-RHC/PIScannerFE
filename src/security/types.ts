/**
 * Core types for the deterministic prompt security engine.
 *
 * The engine is pure TypeScript with no React, DOM or network dependency so it
 * can be unit-tested in isolation and reused elsewhere (CLI, CI check, etc.).
 */

export const CATEGORIES = [
  'PROMPT_INJECTION',
  'DATA_EXFILTRATION',
  'SENSITIVE_DATA',
  'OBFUSCATION',
] as const;

export type Category = (typeof CATEGORIES)[number];

/** Overall / category rating derived from a 0-100 score. */
export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** Severity of an individual finding (a finding is never "safe"). */
export type Severity = Exclude<RiskLevel, 'SAFE'>;

/** A half-open character range `[start, end)`. */
export interface Span {
  start: number;
  end: number;
}

/**
 * Low-level lexical signals extracted from the prompt before rules run.
 * Rules correlate signals; a single signal is rarely a finding on its own.
 */
export type SignalKind =
  | 'injection' // instruction override / jailbreak phrasing
  | 'outbound' // send, upload, POST, email ... (transmission verbs)
  | 'embed' // append to URL, include in request header ... (implicit transmission)
  | 'destination' // URL, email address, webhook, "external server" ...
  | 'sensitive' // API key, password, system prompt, customer records ...
  | 'secret' // a literal credential-like value (JWT, AWS key ...)
  | 'access' // read, extract, dump, reveal ... (verbs that target data)
  | 'obfuscation' // base64, hex, reverse, split, encrypt ...
  | 'concealment'; // silently, don't mention, do not log, avoid detection ...

export interface Signal extends Span {
  kind: SignalKind;
  /** Sub-classification, e.g. `credential`, `url`, `override`. */
  tag: string;
  /** Human-readable description used for tooltips. */
  label: string;
  /** Index of the segment (sentence/clause) containing the signal start. */
  segment: number;
  /** True when preceded by a negation such as "do not" or "never". */
  negated: boolean;
  /** True when inside double quotes (often an example, not an instruction). */
  quoted: boolean;
}

export interface Segment extends Span {
  index: number;
  text: string;
  /**
   * The segment is framed as a question, explanation or description
   * ("Explain...", "Why...", "Best practices for...", "For example...").
   * Educational framing dampens confidence for most rules.
   */
  educational: boolean;
}

/** Highlight styles shown in the UI. */
export type HighlightKind =
  'injection' | 'outbound' | 'sensitive' | 'destination' | 'obfuscation' | 'secret';

export interface EvidenceSpan extends Span {
  kind: HighlightKind;
  label: string;
  /**
   * When set, this span is replaced by the given placeholder everywhere it
   * is displayed (used for opaque payloads that may contain secrets).
   */
  mask?: string;
}

export type SecretType =
  | 'JWT'
  | 'AWS_ACCESS_KEY'
  | 'GITHUB_TOKEN'
  | 'SLACK_TOKEN'
  | 'API_KEY'
  | 'GOOGLE_API_KEY'
  | 'STRIPE_KEY'
  | 'PRIVATE_KEY'
  | 'CONNECTION_STRING'
  | 'BEARER_TOKEN'
  | 'PASSWORD'
  | 'URL_CREDENTIALS'
  | 'SECRET';

/** A credential-like literal value found in the original prompt text. */
export interface SecretMatch extends Span {
  type: SecretType;
  placeholder: string;
}

/**
 * Analysis context handed to every rule. Signal and segment offsets are in
 * the *normalized* text space; the engine maps them back to the original
 * prompt when building findings.
 */
export interface AnalysisContext {
  /** Normalized text (Unicode-folded, zero-width characters removed). */
  readonly text: string;
  readonly segments: readonly Segment[];
  readonly signals: readonly Signal[];
  /** Characters such as zero-width spaces / bidi controls found in the original. */
  readonly invisibleCharCount: number;
  signalsOf(kind: SignalKind, tag?: string): Signal[];
  segmentOf(signal: Span): Segment;
}

export interface RuleHit {
  /** 0..1 — how confident the rule is that this is a genuine instance. */
  confidence: number;
  /** Explanation specific to this hit. */
  explanation: string;
  evidence: EvidenceSpan[];
  /** Optional per-hit override when context escalates/de-escalates severity. */
  severity?: Severity;
  /** Optional per-hit override of the rule's base weight. */
  weight?: number;
}

/**
 * A detection rule. Rules are plain objects so they can be listed, documented
 * and tested individually. `patterns` contains the detection logic: it
 * inspects pre-extracted signals (and may run its own regular expressions)
 * and returns zero or more hits.
 */
export interface Rule {
  id: string;
  category: Category;
  title: string;
  description: string;
  severity: Severity;
  /** Maximum contribution (0-100) of a fully confident hit. */
  weight: number;
  /** Other categories this rule also informs (at reduced weight). */
  relatedCategories?: readonly Category[];
  patterns: (ctx: AnalysisContext) => RuleHit[];
  remediation: string;
}

export type ConfidenceLabel = 'Low' | 'Medium' | 'High';

export interface Finding {
  /** Unique within a scan result. */
  id: string;
  ruleId: string;
  category: Category;
  relatedCategories: readonly Category[];
  severity: Severity;
  confidence: number;
  confidenceLabel: ConfidenceLabel;
  title: string;
  description: string;
  explanation: string;
  /** Redacted, plain-text evidence snippet. Never contains a full secret. */
  evidence: string;
  /** Spans in the ORIGINAL prompt text. */
  evidenceSpans: EvidenceSpan[];
  remediation: string;
  /** Points (0-100 scale) this finding contributes before correlation. */
  contribution: number;
}

export interface CategoryResult {
  category: Category;
  score: number;
  level: RiskLevel;
  findingCount: number;
}

/** A context-correlation adjustment applied on top of weighted findings. */
export interface Correlation {
  id: string;
  description: string;
  /** Minimum score enforced by this correlation (0 when additive only). */
  floor: number;
  /** Points added by this correlation. */
  bonus: number;
}

/** A contiguous run of the original prompt for safe highlighted rendering. */
export interface HighlightRun extends Span {
  /** Already-redacted display text for this run. */
  text: string;
  kind: HighlightKind | null;
  labels: string[];
}

export interface ScanResult {
  score: number;
  level: RiskLevel;
  categories: Record<Category, CategoryResult>;
  findings: Finding[];
  correlations: Correlation[];
  highlights: HighlightRun[];
  secretsRedacted: number;
  inputLength: number;
  truncated: boolean;
}

export interface ScanOptions {
  /** Characters beyond this length are not analyzed. Default 100,000. */
  maxLength?: number;
}
