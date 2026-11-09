import { describe, expect, it } from 'vitest';
import swaConfig from '../../public/staticwebapp.config.json';
import pkg from '../../package.json';

/**
 * Static guardrails: read every application source file (excluding tests)
 * and assert that no network, persistence, telemetry or raw-HTML API is used.
 * ESLint enforces the same rules; this test is a second, independent check.
 */
const sources = import.meta.glob<string>(
  ['../**/*.{ts,tsx}', '!../**/*.test.{ts,tsx}', '!../test/**'],
  {
    query: '?raw',
    import: 'default',
    eager: true,
  },
);

const FORBIDDEN: [string, RegExp][] = [
  ['fetch()', /\bfetch\s*\(/],
  ['XMLHttpRequest', /\bXMLHttpRequest\b/],
  ['WebSocket', /\bnew\s+WebSocket\b/],
  ['EventSource', /\bEventSource\b/],
  ['sendBeacon', /\bsendBeacon\b/],
  ['localStorage', /\blocalStorage\b/],
  ['sessionStorage', /\bsessionStorage\b/],
  ['indexedDB', /\bindexedDB\b/],
  ['document.cookie', /\bdocument\.cookie\b/],
  ['dangerouslySetInnerHTML prop', /dangerouslySetInnerHTML\s*=/],
  ['innerHTML assignment', /\.(?:inner|outer)HTML\s*=/],
  ['insertAdjacentHTML', /insertAdjacentHTML/],
  ['eval', /\beval\s*\(/],
  ['new Function', /\bnew\s+Function\s*\(/],
  ['window.open', /\bwindow\.open\s*\(/],
  ['anchor element', /<a[\s>]/],
  ['dynamic import of URL', /import\s*\(\s*['"`]https?:/],
];

/** Removes comments so documentation that *mentions* an API is not a false positive. */
const stripComments = (src: string) =>
  src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\\])\/\/.*$/gm, '$1');

describe('source guardrails', () => {
  const files = Object.entries(sources).map(([f, src]) => [f, stripComments(src)] as const);

  it('finds application sources to check', () => {
    expect(files.length).toBeGreaterThan(10);
  });

  it.each(FORBIDDEN)('application code does not use %s', (_name, pattern) => {
    const offenders = files.filter(([, src]) => pattern.test(src)).map(([file]) => file);
    expect(offenders).toEqual([]);
  });

  it('the detection engine is independent from React and the DOM', () => {
    const engine = files.filter(([file]) => file.startsWith('../security/'));
    expect(engine.length).toBeGreaterThan(5);
    for (const [file, src] of engine) {
      expect(src, file).not.toMatch(/from ['"]react/);
      expect(src, file).not.toMatch(/\bdocument\.|\bwindow\./);
    }
  });

  it('has no backend / AI SDK / analytics dependencies', () => {
    const deps = Object.keys({ ...pkg.dependencies });
    expect(deps.sort()).toEqual(
      ['@fluentui/react-components', '@fluentui/react-icons', 'react', 'react-dom'].sort(),
    );
  });
});

describe('Azure Static Web Apps security headers', () => {
  const headers = swaConfig.globalHeaders as Record<string, string>;
  const csp = headers['Content-Security-Policy'] ?? '';
  const directive = (name: string) =>
    csp
      .split(';')
      .map((d) => d.trim())
      .find((d) => d.startsWith(`${name} `));

  it.each([
    ['default-src', "default-src 'self'"],
    ['script-src', "script-src 'self'"],
    ['style-src', "style-src 'self'"],
    ['img-src', "img-src 'self' data:"],
    ['font-src', "font-src 'self'"],
    ['connect-src', "connect-src 'self'"],
    ['object-src', "object-src 'none'"],
    ['frame-src', "frame-src 'none'"],
    ['frame-ancestors', "frame-ancestors 'none'"],
    ['base-uri', "base-uri 'self'"],
    ['form-action', "form-action 'self'"],
  ])('CSP %s is restrictive', (name, expected) => {
    expect(directive(name)).toBe(expected);
  });

  it('CSP never allows unsafe-eval or unsafe-inline', () => {
    expect(csp).not.toMatch(/unsafe-eval|unsafe-inline|\*/);
  });

  it('sets hardening headers', () => {
    expect(headers['X-Content-Type-Options']).toBe('nosniff');
    expect(headers['Referrer-Policy']).toBe('no-referrer');
    expect(headers['Permissions-Policy']).toMatch(/camera=\(\), microphone=\(\), geolocation=\(\)/);
  });
});
