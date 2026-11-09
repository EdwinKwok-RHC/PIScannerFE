/**
 * Text normalization with an index map back to the original string.
 *
 * Attackers commonly evade keyword filters with full-width letters, Cyrillic
 * look-alikes, smart quotes or zero-width characters (e.g. "ig" + U+200B + "nore").
 * Normalization folds these so the lexicon matches, while `toOriginal` lets
 * the engine report evidence against the exact characters the user pasted.
 */

/** Zero-width and bidirectional control characters (often used for evasion). */
const INVISIBLE = /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/;

/** Common Cyrillic/Greek homoglyphs of Latin letters. */
const HOMOGLYPHS: Record<string, string> = {
  а: 'a',
  е: 'e',
  о: 'o',
  р: 'p',
  с: 'c',
  х: 'x',
  у: 'y',
  і: 'i',
  ј: 'j',
  ѕ: 's',
  А: 'A',
  В: 'B',
  Е: 'E',
  К: 'K',
  М: 'M',
  Н: 'H',
  О: 'O',
  Р: 'P',
  С: 'C',
  Т: 'T',
  Х: 'X',
  ο: 'o',
  α: 'a',
  ε: 'e',
  ι: 'i',
  ν: 'v',
};

const PUNCTUATION: Record<string, string> = {
  '\u2018': "'",
  '\u2019': "'",
  '\u201A': "'",
  '\u201B': "'",
  '\u201C': '"',
  '\u201D': '"',
  '\u201E': '"',
  '\u2032': "'",
  '\u2010': '-',
  '\u2011': '-',
  '\u2012': '-',
  '\u2013': '-',
  '\u2014': '-',
  '\u00A0': ' ',
  '\u2007': ' ',
  '\u202F': ' ',
};

export interface NormalizedText {
  text: string;
  /** `map[i]` = index in the original string of normalized character `i`. */
  map: number[];
  /** `reverse[j]` = first normalized index at or after original index `j`. */
  reverse: number[];
  invisibleCharCount: number;
}

export function normalizeText(original: string): NormalizedText {
  let text = '';
  const map: number[] = [];
  const reverse: number[] = new Array<number>(original.length + 1);
  let invisibleCharCount = 0;

  // Iterate by code point so surrogate pairs stay intact.
  let i = 0;
  for (const ch of original) {
    reverse[i] = text.length;
    if (ch.length === 2) reverse[i + 1] = text.length;

    let out: string;
    if (INVISIBLE.test(ch)) {
      invisibleCharCount++;
      out = '';
    } else {
      const mapped = PUNCTUATION[ch] ?? HOMOGLYPHS[ch];
      if (mapped !== undefined) {
        out = mapped;
      } else if (ch.charCodeAt(0) < 0x80) {
        out = ch;
      } else {
        // NFKC folds full-width / stylistic letters (e.g. "ｉｇｎｏｒｅ", "𝐢𝐠𝐧𝐨𝐫𝐞").
        out = ch.normalize('NFKC');
      }
    }
    for (let k = 0; k < out.length; k++) map.push(i);
    text += out;
    i += ch.length;
  }
  reverse[original.length] = text.length;
  return { text, map, reverse, invisibleCharCount };
}

/** Converts a normalized span to an original-text span. */
export function toOriginalSpan(
  norm: NormalizedText,
  start: number,
  end: number,
  original: string,
): { start: number; end: number } {
  if (norm.map.length === 0) return { start: 0, end: 0 };
  const s = norm.map[Math.min(start, norm.map.length - 1)] ?? 0;
  const lastIdx = Math.max(start, end - 1);
  const lastOrig = norm.map[Math.min(lastIdx, norm.map.length - 1)] ?? s;
  // Include the whole code point of the last character (surrogate pairs).
  const cp = original.codePointAt(lastOrig) ?? 0;
  const e = lastOrig + (cp > 0xffff ? 2 : 1);
  return { start: s, end: Math.min(Math.max(e, s), original.length) };
}

/** Converts an original-text span to a normalized span. */
export function toNormalizedSpan(
  norm: NormalizedText,
  start: number,
  end: number,
): { start: number; end: number } {
  return { start: norm.reverse[start] ?? 0, end: norm.reverse[end] ?? norm.text.length };
}
