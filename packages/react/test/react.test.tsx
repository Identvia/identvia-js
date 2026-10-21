import { describe, expect, it, vi, beforeEach } from 'vitest';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { IdentviaClient } from '@identvia/js';
import { IdentviaProvider, SignInWithIdentvia, SignedIn, SignedOut, useIdentvia } from '../src/index.js';
import { createFake, ISSUER } from '../../js/test/fake-identvia.js';

let assigned: string[] = [];
beforeEach(() => {
  cleanup();
  assigned = [];
  sessionStorage.clear();
  window.history.replaceState(null, '', '/');
  vi.spyOn(window.location, 'assign').mockImplementation((u: string | URL) => { assigned.push(String(u)); });
});

function Profile() {
  const { user, signOut } = useIdentvia();
  return <div><span data-testid="email">{user?.email}</span><button onClick={() => signOut()}>out</button></div>;
}

describe('@identvia/react', () => {
  it('button markup matches button.js (classes, data attributes, mark, label)', () => {
    render(<SignInWithIdentvia href="/auth/login" theme="dark" size="large" shape="pill" text="continue" />);
    const a = screen.getByRole('link', { name: 'Continue with Identvia' });
    expect(a.className).toBe('identvia-btn');
    expect(a.getAttribute('data-theme')).toBe('dark');
    expect(a.getAttribute('data-size')).toBe('large');
    expect(a.getAttribute('data-shape')).toBe('pill');
    expect(a.querySelector('svg.idv-mark rect')!.getAttribute('fill')).toBe('#4B4ACF');
    expect(a.querySelector('.idv-label')!.textContent).toBe('Continue with Identvia');
    expect(document.documentElement.hasAttribute('data-identvia-css')).toBe(true);
  });
  it('refuses javascript: hrefs and labels icon-only buttons', () => {
    render(<SignInWithIdentvia href="javascript:alert(1)" text="icon" />);
    const a = document.querySelector('a.identvia-btn')!;
    expect(a.getAttribute('href')).toBeNull();
    expect(a.getAttribute('aria-label')).toBe('Sign in with Identvia');
  });
  it('full flow: button → redirect → provider handles the callback → SignedIn', async () => {
    const f = await createFake();
    const client = new IdentviaClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: 'https://app.example.com/callback', fetch: f.fetch, storage: 'session' });
    const tree = (
      <IdentviaProvider client={client}>
        <SignedOut><SignInWithIdentvia authorizeOptions={{ returnTo: '/home' }} /></SignedOut>
        <SignedIn><Profile /></SignedIn>
      </IdentviaProvider>
    );
    const { unmount } = render(tree);
    const btn = await screen.findByRole('button', { name: 'Sign in with Identvia' });
    await act(async () => { fireEvent.click(btn); });
    await waitFor(() => expect(assigned.length).toBe(1));
    unmount();
    const cb = new URL(f.authorize(assigned[0]!));
    window.history.replaceState(null, '', cb.pathname + cb.search);
    render(tree);
    expect(await screen.findByTestId('email')).toHaveProperty('textContent', 'ada@example.com');
    expect(window.location.pathname).toBe('/home');
    expect(window.location.search).toBe('');
    await act(async () => { fireEvent.click(screen.getByText('out')); });
    expect(await screen.findByRole('button', { name: 'Sign in with Identvia' })).toBeTruthy();
  });
  it('useIdentvia outside the provider throws a clear error', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => render(<Profile />)).toThrow(/inside <IdentviaProvider>/);
    spy.mockRestore();
  });
});
