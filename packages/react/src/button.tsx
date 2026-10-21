import { useEffect, type AnchorHTMLAttributes, type ButtonHTMLAttributes, type CSSProperties, type MouseEvent } from 'react';
import type { AuthorizeOptions } from '@identvia/js';
import { BUTTON_CSS } from './button-css.js';
import { useOptionalIdentvia } from './provider.js';

const LABELS = { signin: 'Sign in with Identvia', continue: 'Continue with Identvia', signup: 'Sign up with Identvia', icon: 'Sign in with Identvia' } as const;

let injected = false;
/** Adds the button stylesheet once, CSP-safe (constructable stylesheet, no inline <style>). */
export function ensureButtonStyles(doc: Document | undefined = typeof document !== 'undefined' ? document : undefined): void {
  if (!doc || injected || doc.documentElement.hasAttribute('data-identvia-css')) return;
  injected = true;
  doc.documentElement.setAttribute('data-identvia-css', '');
  try {
    if ('adoptedStyleSheets' in doc && typeof CSSStyleSheet === 'function' && 'replaceSync' in CSSStyleSheet.prototype) {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(BUTTON_CSS);
      doc.adoptedStyleSheets = [...doc.adoptedStyleSheets, sheet];
      return;
    }
  } catch { /* fall through */ }
  const l = doc.createElement('link');
  l.rel = 'stylesheet';
  l.href = 'https://id.identvia.com/sdk/v1/button.css?v=1.0.0';
  l.setAttribute('data-identvia-css', '');
  doc.head.appendChild(l);
}

export function IdentviaMark() {
  return (
    <svg viewBox="0 0 28 28" className="idv-mark" aria-hidden="true" focusable="false">
      <rect width="28" height="28" rx="8" fill="#4B4ACF" />
      <circle cx="9.25" cy="8.25" r="2.1" fill="#fff" />
      <path d="M8.6 13.4l3.9 6.1L20.4 8" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export interface SignInWithIdentviaProps {
  theme?: 'light' | 'dark' | 'brand' | 'auto';
  size?: 'small' | 'medium' | 'large';
  shape?: 'rect' | 'rounded' | 'pill';
  text?: keyof typeof LABELS;
  /** 'full' or a pixel width 120–400. */
  width?: 'full' | number;
  /** Server-rendered apps: link to your login route (e.g. "/auth/login"). Without it the provider's signIn is used. */
  href?: string;
  /** 'redirect' (default) or 'popup'. Only without href. */
  mode?: 'redirect' | 'popup';
  authorizeOptions?: AuthorizeOptions;
  label?: string;
  className?: string;
  style?: CSSProperties;
  disabled?: boolean;
  onClick?: (e: MouseEvent<HTMLElement>) => void;
}

/** The official Identvia button: same look, sizes, themes and accessibility as button.js. */
export function SignInWithIdentvia(p: SignInWithIdentviaProps & Omit<ButtonHTMLAttributes<HTMLButtonElement> & AnchorHTMLAttributes<HTMLAnchorElement>, keyof SignInWithIdentviaProps>) {
  const { theme = 'light', size = 'medium', shape = 'rounded', text = 'signin', width, href, mode = 'redirect', authorizeOptions, label, className, style, disabled, onClick, ...rest } = p;
  useEffect(() => { ensureButtonStyles(); }, []);
  const ctx = useOptionalIdentvia();
  const l = label && label.length <= 60 ? label : LABELS[text];
  const s: CSSProperties = { ...style };
  if (typeof width === 'number') s.width = `${Math.max(120, Math.min(400, width))}px`;
  const common = {
    className: ['identvia-btn', className].filter(Boolean).join(' '),
    'data-identvia-ready': '',
    'data-theme': theme, 'data-size': size, 'data-shape': shape, 'data-text': text,
    ...(width === 'full' ? { 'data-width': 'full' } : {}),
    ...(text === 'icon' ? { 'aria-label': l, title: l } : {}),
    style: s,
  };
  const children = (<><IdentviaMark /><span className="idv-label">{l}</span></>);
  if (href !== undefined) {
    const safe = /^(https:|\/(?![/\\]))/i.test(href) ? href : undefined;
    return <a {...rest} {...common} href={safe} aria-disabled={disabled || undefined} onClick={onClick}>{children}</a>;
  }
  const handle = (e: MouseEvent<HTMLButtonElement>) => {
    onClick?.(e);
    if (e.defaultPrevented || !ctx) return;
    if (mode === 'popup') void ctx.signInWithPopup(authorizeOptions).catch(() => undefined);
    else void ctx.signIn(authorizeOptions);
  };
  return <button type="button" {...rest} {...common} disabled={disabled} onClick={handle}>{children}</button>;
}
