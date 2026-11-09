/**
 * CSP compatibility adapter for Fluent UI (Griffel) under `style-src 'self'`.
 *
 * Fluent UI v9 injects its CSS at runtime by creating `<style>` elements and
 * calling `element.sheet.insertRule()`. A strict Content Security Policy
 * without `'unsafe-inline'` blocks those elements, and the browser then
 * reports `element.sheet === null`, so every Fluent component would render
 * unstyled.
 *
 * Rather than weakening the CSP with `'unsafe-inline'`, this adapter backs any
 * CSP-blocked `<style>` element with a *constructable stylesheet*
 * (`new CSSStyleSheet()` + `document.adoptedStyleSheets`). Constructable
 * stylesheets are created through the CSSOM API and are permitted under
 * `style-src 'self'`. Only style rules produced by the application's own
 * bundled code can reach them; no user content is ever written to CSS.
 *
 * The adapter is a no-op when inline styles are allowed (development server,
 * tests) or when the browser lacks constructable stylesheet support.
 */
export function installCspStyleAdapter(doc: Document = document): boolean {
  const win = doc.defaultView;
  if (!win || !('adoptedStyleSheets' in doc) || typeof win.CSSStyleSheet !== 'function') {
    return false;
  }
  const proto = win.HTMLStyleElement.prototype;
  const descriptor = Object.getOwnPropertyDescriptor(proto, 'sheet');
  // The native getter is always invoked with an explicit receiver via .call().
  // eslint-disable-next-line @typescript-eslint/unbound-method
  const nativeGet = descriptor?.get;
  if (!nativeGet || !descriptor.configurable) return false;

  // Probe: is a freshly inserted <style> element blocked by CSP?
  const probe = doc.createElement('style');
  probe.setAttribute('data-csp-probe', '');
  doc.head.appendChild(probe);
  const blocked = nativeGet.call(probe) === null;
  probe.remove();
  if (!blocked) return false;

  const fallback = new WeakMap<HTMLStyleElement, CSSStyleSheet>();
  const owned = new WeakSet<CSSStyleSheet>();

  /** Keeps adopted sheets in the same order as their <style> elements. */
  const sync = () => {
    const ordered: CSSStyleSheet[] = [];
    doc.querySelectorAll('style').forEach((el) => {
      const sheet = fallback.get(el);
      if (sheet) {
        sheet.media.mediaText = el.media;
        ordered.push(sheet);
      }
    });
    const foreign = doc.adoptedStyleSheets.filter((s) => !owned.has(s));
    doc.adoptedStyleSheets = [...foreign, ...ordered];
  };

  Object.defineProperty(proto, 'sheet', {
    configurable: true,
    enumerable: descriptor.enumerable ?? true,
    get(this: HTMLStyleElement): CSSStyleSheet | null {
      const native = nativeGet.call(this) as CSSStyleSheet | null;
      if (native || !this.isConnected || this.ownerDocument !== doc) return native;
      let sheet = fallback.get(this);
      if (!sheet) {
        sheet = new win.CSSStyleSheet({ media: this.media });
        fallback.set(this, sheet);
        owned.add(sheet);
        sync();
      }
      return sheet;
    },
  });

  // Drop sheets of removed <style> elements and re-order after insertions.
  new win.MutationObserver(sync).observe(doc.head, { childList: true });
  return true;
}
