import type { SecretMatch, SecretType, Span } from './types';

/**
 * Deterministic detectors for credential-like literal values.
 *
 * Every piece of evidence shown in the UI is passed through `redactRange` /
 * `redactSecrets`, so a complete detected secret is never displayed. Where a
 * detector has a "prefix" (e.g. `password=`), only the value is replaced so
 * the user can still see *what kind* of secret was present.
 */
interface SecretDetector {
  type: SecretType;
  pattern: RegExp;
  /** Capture group holding the secret value (0 = whole match). */
  group?: number;
}

const DETECTORS: SecretDetector[] = [
  {
    type: 'PRIVATE_KEY',
    pattern:
      /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----|$)/g,
  },
  {
    type: 'JWT',
    pattern:
      /\beyJ[A-Za-z0-9_-]{5,}\.(?:eyJ[A-Za-z0-9_-]*|[A-Za-z0-9_-]{2,})(?:\.[A-Za-z0-9_-]*)?/g,
  },
  { type: 'AWS_ACCESS_KEY', pattern: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g },
  {
    type: 'GITHUB_TOKEN',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g,
  },
  { type: 'SLACK_TOKEN', pattern: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { type: 'GOOGLE_API_KEY', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: 'STRIPE_KEY', pattern: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  // OpenAI / Anthropic / generic "sk-" style keys.
  { type: 'API_KEY', pattern: /\bsk-(?:ant-|proj-|live-)?[A-Za-z0-9_-]{20,}/g },
  {
    type: 'CONNECTION_STRING',
    pattern:
      /\b(?:DefaultEndpointsProtocol=[^\s;]+;[^\s"']*?(?:AccountKey|SharedAccessSignature)=[^\s;"']+(?:;[^\s"']*)?|(?:Server|Data Source|Host)=[^;\n]+;[^\n"']*?(?:Password|Pwd)=[^;\s"']+;?|Endpoint=sb:\/\/[^\s;]+;[^\s"']*?SharedAccessKey=[^\s;"']+)/gi,
  },
  {
    type: 'CONNECTION_STRING',
    pattern:
      /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?|mssql):\/\/[^\s:@/]+:[^\s@/]+@[^\s"']+/gi,
  },
  { type: 'URL_CREDENTIALS', pattern: /\bhttps?:\/\/[^\s:@/]+:([^\s@/]+)@/gi, group: 1 },
  { type: 'BEARER_TOKEN', pattern: /\bBearer\s+([A-Za-z0-9\-._~+/]{16,}=*)/g, group: 1 },
  {
    type: 'PASSWORD',
    pattern: /\b(?:password|passwd|pwd|passphrase)\s*[:=]\s*["']?([^\s"',;]{4,})/gi,
    group: 1,
  },
  {
    type: 'SECRET',
    pattern:
      /\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|account[_-]?key|sas)\s*[:=]\s*["']?([A-Za-z0-9._\-/+=]{12,})/gi,
    group: 1,
  },
  {
    // Sensitive query-string parameter values: ?token=..., &api_key=...
    type: 'SECRET',
    pattern:
      /[?&](?:token|access_token|refresh_token|id_token|api_key|apikey|key|secret|password|sig|signature|code|auth)=([^&\s#"']{6,})/gi,
    group: 1,
  },
];

const PLACEHOLDERS: Record<SecretType, string> = {
  JWT: '[REDACTED_JWT]',
  AWS_ACCESS_KEY: '[REDACTED_AWS_ACCESS_KEY]',
  GITHUB_TOKEN: '[REDACTED_GITHUB_TOKEN]',
  SLACK_TOKEN: '[REDACTED_SLACK_TOKEN]',
  API_KEY: '[REDACTED_API_KEY]',
  GOOGLE_API_KEY: '[REDACTED_API_KEY]',
  STRIPE_KEY: '[REDACTED_API_KEY]',
  PRIVATE_KEY: '[REDACTED_PRIVATE_KEY]',
  CONNECTION_STRING: '[REDACTED_CONNECTION_STRING]',
  BEARER_TOKEN: '[REDACTED_BEARER_TOKEN]',
  PASSWORD: '[REDACTED_PASSWORD]',
  URL_CREDENTIALS: '[REDACTED_CREDENTIALS]',
  SECRET: '[REDACTED_SECRET]',
};

/** Values that look like assignments but are clearly placeholders. */
const PLACEHOLDER_VALUE =
  /^(?:\*+|x+|\.{3,}|<[^>]*>|\{[^}]*\}|\$\{?[A-Za-z_]+\}?|your[_-]|changeme$|example$)/i;

/** Finds credential-like values in `text`. Results are sorted and non-overlapping. */
export function findSecrets(text: string): SecretMatch[] {
  const found: SecretMatch[] = [];
  for (const d of DETECTORS) {
    d.pattern.lastIndex = 0;
    for (const m of text.matchAll(d.pattern)) {
      const group = d.group ?? 0;
      const value = m[group];
      if (value === undefined || value.length === 0) continue;
      if (group > 0 && PLACEHOLDER_VALUE.test(value)) continue;
      const offset = group > 0 ? m[0].lastIndexOf(value) : 0;
      const start = m.index + offset;
      found.push({
        start,
        end: start + value.length,
        type: d.type,
        placeholder: PLACEHOLDERS[d.type],
      });
    }
  }
  // Earlier detectors are more specific; keep the longest/earliest non-overlapping set.
  found.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
  const result: SecretMatch[] = [];
  for (const s of found) {
    const last = result[result.length - 1];
    if (last && s.start < last.end) {
      if (s.end > last.end && s.start === last.start) result[result.length - 1] = s;
      continue;
    }
    result.push(s);
  }
  return result;
}

/**
 * Returns `text.slice(range.start, range.end)` with any intersecting secret
 * replaced by its placeholder. Partially included secrets are fully redacted.
 */
export function redactRange(text: string, range: Span, secrets: readonly SecretMatch[]): string {
  let out = '';
  let cursor = range.start;
  for (const s of secrets) {
    if (s.end <= range.start || s.start >= range.end) continue;
    if (s.start > cursor) out += text.slice(cursor, s.start);
    out += s.placeholder;
    cursor = Math.max(cursor, s.end);
  }
  if (cursor < range.end) out += text.slice(cursor, range.end);
  return out;
}

/** Redacts every credential-like value in an arbitrary string. */
export function redactSecrets(text: string): string {
  return redactRange(text, { start: 0, end: text.length }, findSecrets(text));
}
