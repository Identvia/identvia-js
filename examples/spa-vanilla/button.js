/*! Identvia sign-in button v1 · MIT · https://identvia.com/developers/docs/button
 * Presentation only: no network calls, no cookies, no tracking, no secrets.
 * CSP-safe: no inline script/style, no eval, no innerHTML (Trusted Types friendly).
 */
(function (w, d) {
  'use strict';
  if (w.IdentviaButton) { return; }
  var VERSION = '1.0.0';
  var CSS = ".identvia-btn{--idv-h:40px;--idv-px:16px;--idv-fs:14px;--idv-gap:10px;--idv-icon:20px;--idv-r:8px;box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;gap:var(--idv-gap);height:var(--idv-h);min-width:var(--idv-h);padding:0 var(--idv-px);border-radius:var(--idv-r);margin:0;font:600 var(--idv-fs)/1 \"Inter Variable\",Inter,-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,Helvetica,Arial,sans-serif;letter-spacing:-.006em;white-space:nowrap;text-decoration:none;cursor:pointer;-webkit-user-select:none;user-select:none;border:1px solid #d4d4d8;background:#fff;color:#18181b;box-shadow:0 1px 2px rgba(0,0,0,.05);transition:background-color .15s,border-color .15s,box-shadow .15s;-webkit-tap-highlight-color:transparent}.identvia-btn:hover{background:#f4f4f5;border-color:#a1a1aa;color:#18181b}.identvia-btn:active{background:#e4e4e7}.identvia-btn:focus{outline:none}.identvia-btn:focus-visible{outline:2px solid #4b4acf;outline-offset:2px}.identvia-btn[aria-disabled=true],.identvia-btn:disabled{opacity:.5;pointer-events:none}.identvia-btn .idv-mark{width:var(--idv-icon);height:var(--idv-icon);flex:none;display:block}.identvia-btn .idv-label{display:inline-block;overflow:hidden;text-overflow:ellipsis}.identvia-btn[data-theme=dark]{background:#18181b;border-color:#3f3f46;color:#fff;box-shadow:none}.identvia-btn[data-theme=dark]:hover{background:#27272a;border-color:#52525b;color:#fff}.identvia-btn[data-theme=dark]:focus-visible{outline-color:#8585f0}.identvia-btn[data-theme=brand]{background:#4b4acf;border-color:#4b4acf;color:#fff}.identvia-btn[data-theme=brand]:hover{background:#3d3cb4;border-color:#3d3cb4;color:#fff}@media (prefers-color-scheme:dark){.identvia-btn[data-theme=auto]{background:#18181b;border-color:#3f3f46;color:#fff;box-shadow:none}.identvia-btn[data-theme=auto]:hover{background:#27272a;border-color:#52525b;color:#fff}.identvia-btn[data-theme=auto]:focus-visible{outline-color:#8585f0}}.identvia-btn[data-size=small]{--idv-h:32px;--idv-px:12px;--idv-fs:13px;--idv-gap:8px;--idv-icon:16px;--idv-r:6px}.identvia-btn[data-size=large]{--idv-h:48px;--idv-px:20px;--idv-fs:16px;--idv-gap:12px;--idv-icon:22px;--idv-r:10px}.identvia-btn[data-shape=rect]{--idv-r:4px}.identvia-btn[data-shape=pill]{--idv-r:999px}.identvia-btn[data-width=full]{display:flex;width:100%}.identvia-btn[data-text=icon]{padding:0;width:var(--idv-h)}.identvia-btn[data-text=icon] .idv-label{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}@media (forced-colors:active){.identvia-btn,.identvia-btn[data-theme]{border:1px solid ButtonText;background:ButtonFace;color:ButtonText;forced-color-adjust:none}.identvia-btn:focus-visible{outline:2px solid Highlight}.identvia-btn .idv-mark rect{fill:ButtonText}.identvia-btn .idv-mark circle,.identvia-btn .idv-mark path{fill:ButtonFace;stroke:ButtonFace}.identvia-btn .idv-mark circle{stroke:none}.identvia-btn .idv-mark path{fill:none}}@media (prefers-reduced-motion:reduce){.identvia-btn{transition:none}}";
  var SVG = 'http://www.w3.org/2000/svg';
  var LABELS = { signin: 'Sign in with Identvia', continue: 'Continue with Identvia', signup: 'Sign up with Identvia', icon: 'Sign in with Identvia' };
  var ALLOWED = { theme: ['light', 'dark', 'brand', 'auto'], size: ['small', 'medium', 'large'], shape: ['rect', 'rounded', 'pill'], text: ['signin', 'continue', 'signup', 'icon'] };

  function scriptOrigin() {
    var s = d.currentScript;
    try { return s && s.src ? new URL(s.src).origin : null; } catch (e) { return null; }
  }
  var ORIGIN = scriptOrigin();

  function styles() {
    if (d.querySelector('link[data-identvia-css],style[data-identvia-css]') || d.documentElement.hasAttribute('data-identvia-css')) { return; }
    d.documentElement.setAttribute('data-identvia-css', '');
    // 1) Constructable stylesheet: not an inline <style>, so it works under a strict style-src.
    try {
      if ('adoptedStyleSheets' in d && typeof CSSStyleSheet === 'function' && 'replaceSync' in CSSStyleSheet.prototype) {
        var sheet = new CSSStyleSheet();
        sheet.replaceSync(CSS);
        d.adoptedStyleSheets = d.adoptedStyleSheets.concat([sheet]);
        return;
      }
    } catch (e) { /* fall through */ }
    // 2) Older browsers: the same rules as a stylesheet from this script's origin.
    if (ORIGIN) {
      var l = d.createElement('link');
      l.rel = 'stylesheet';
      l.href = ORIGIN + '/sdk/v1/button.css?v=' + VERSION;
      l.setAttribute('data-identvia-css', '');
      (d.head || d.documentElement).appendChild(l);
    }
  }

  function mark() {
    var s = d.createElementNS(SVG, 'svg');
    s.setAttribute('viewBox', '0 0 28 28');
    s.setAttribute('class', 'idv-mark');
    s.setAttribute('aria-hidden', 'true');
    s.setAttribute('focusable', 'false');
    var r = d.createElementNS(SVG, 'rect');
    r.setAttribute('width', '28'); r.setAttribute('height', '28'); r.setAttribute('rx', '8'); r.setAttribute('fill', '#4B4ACF');
    var c = d.createElementNS(SVG, 'circle');
    c.setAttribute('cx', '9.25'); c.setAttribute('cy', '8.25'); c.setAttribute('r', '2.1'); c.setAttribute('fill', '#fff');
    var p = d.createElementNS(SVG, 'path');
    p.setAttribute('d', 'M8.6 13.4l3.9 6.1L20.4 8');
    p.setAttribute('fill', 'none'); p.setAttribute('stroke', '#fff'); p.setAttribute('stroke-width', '2.6');
    p.setAttribute('stroke-linecap', 'round'); p.setAttribute('stroke-linejoin', 'round');
    s.appendChild(r); s.appendChild(c); s.appendChild(p);
    return s;
  }

  function opt(el, name, fallback) {
    var v = (el.getAttribute('data-' + name) || '').toLowerCase();
    return ALLOWED[name].indexOf(v) >= 0 ? v : fallback;
  }

  function render(el) {
    if (!el || el.nodeType !== 1 || el.hasAttribute('data-identvia-ready')) { return; }
    el.setAttribute('data-identvia-ready', '');
    var text = opt(el, 'text', 'signin');
    el.setAttribute('data-theme', opt(el, 'theme', 'light'));
    el.setAttribute('data-size', opt(el, 'size', 'medium'));
    el.setAttribute('data-shape', opt(el, 'shape', 'rounded'));
    el.setAttribute('data-text', text);
    var width = el.getAttribute('data-width');
    if (width && width !== 'full' && /^\d{2,3}$/.test(width)) { el.style.width = Math.max(120, Math.min(400, +width)) + 'px'; }
    var own = (el.textContent || '').replace(/\s+/g, ' ').trim();
    var label = own && own.length <= 60 ? own : LABELS[text];
    while (el.firstChild) { el.removeChild(el.firstChild); }
    el.appendChild(mark());
    var span = d.createElement('span');
    span.className = 'idv-label';
    span.textContent = label;
    el.appendChild(span);
    if (text === 'icon') { el.setAttribute('aria-label', label); if (!el.title) { el.title = label; } }
    var tag = el.tagName;
    if (tag !== 'A' && tag !== 'BUTTON') {
      // A <div> placeholder becomes keyboard-operable: Enter/Space follow data-href.
      el.setAttribute('role', 'link');
      if (!el.hasAttribute('tabindex')) { el.setAttribute('tabindex', '0'); }
      var go = function () { var h = el.getAttribute('data-href'); if (h && /^(https:|\/)/i.test(h)) { w.location.assign(h); } };
      el.addEventListener('click', go);
      el.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
    } else if (tag === 'BUTTON' && !el.getAttribute('type')) {
      el.setAttribute('type', 'submit');
    }
  }

  function scan(root) {
    styles();
    var list = (root || d).querySelectorAll('.identvia-btn:not([data-identvia-ready])');
    for (var i = 0; i < list.length; i++) { render(list[i]); }
  }

  w.IdentviaButton = { version: VERSION, render: function (el) { styles(); if (el) { el.classList.add('identvia-btn'); render(el); } else { scan(d); } } };
  if (d.readyState === 'loading') { d.addEventListener('DOMContentLoaded', function () { scan(d); }); } else { scan(d); }
})(window, document);
