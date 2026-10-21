import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { IdentviaClient, type AuthorizeOptions, type IdentviaClientOptions, type IdTokenClaims } from '@identvia/js';

export interface IdentviaState {
  isLoading: boolean;
  isAuthenticated: boolean;
  user: IdTokenClaims | null;
  error: Error | null;
}

export interface IdentviaContextValue extends IdentviaState {
  client: IdentviaClient;
  signIn(opts?: AuthorizeOptions): Promise<void>;
  signInWithPopup(opts?: AuthorizeOptions): Promise<void>;
  signOut(opts?: { federated?: boolean; postLogoutRedirectUri?: string }): Promise<void>;
  getAccessToken(opts?: { forceRefresh?: boolean }): Promise<string>;
}

const Ctx = createContext<IdentviaContextValue | null>(null);

export interface IdentviaProviderProps extends Partial<IdentviaClientOptions> {
  children?: ReactNode;
  /** Bring your own client (otherwise one is created from the props). */
  client?: IdentviaClient;
  /** Called after the redirect callback is handled. Default: history.replaceState to returnTo. */
  onRedirectCallback?: (result: { returnTo?: string; user: IdTokenClaims }) => void;
  /** Handle ?code=&state= automatically on mount when the URL matches redirectUri. Default true. */
  handleRedirect?: boolean;
}

export function IdentviaProvider({ children, client: given, onRedirectCallback, handleRedirect = true, ...opts }: IdentviaProviderProps) {
  const clientRef = useRef<IdentviaClient | null>(given ?? null);
  if (!clientRef.current) clientRef.current = new IdentviaClient(opts as IdentviaClientOptions);
  const client = clientRef.current;
  const [state, setState] = useState<IdentviaState>({ isLoading: true, isAuthenticated: false, user: null, error: null });
  const handled = useRef(false);

  useEffect(() => {
    const unsub = client.subscribe((e) => {
      if (e.type === 'signedOut') setState({ isLoading: false, isAuthenticated: false, user: null, error: null });
      else setState({ isLoading: false, isAuthenticated: true, user: e.session.user, error: null });
    });
    (async () => {
      try {
        const here = new URL(window.location.href);
        const ru = new URL(client.oidc.redirectUri);
        if (handleRedirect && !handled.current && here.origin === ru.origin && here.pathname === ru.pathname && IdentviaClient.isRedirectCallback(here.href)) {
          handled.current = true; // StrictMode runs effects twice; the code is single-use
          const r = await client.handleRedirectCallback(here.href);
          if (onRedirectCallback) onRedirectCallback(r);
          else if (r.returnTo) window.history.replaceState(null, '', r.returnTo);
        }
        const user = await client.getUser();
        const authed = await client.isAuthenticated();
        setState({ isLoading: false, isAuthenticated: authed, user: authed ? user : null, error: null });
      } catch (error) {
        setState({ isLoading: false, isAuthenticated: false, user: null, error: error as Error });
      }
    })();
    return () => { unsub(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client]);

  const signIn = useCallback((o?: AuthorizeOptions) => client.signInWithRedirect(o), [client]);
  const signInWithPopup = useCallback(async (o?: AuthorizeOptions) => {
    try { await client.signInWithPopup(o); } catch (error) { setState((s) => ({ ...s, error: error as Error })); throw error; }
  }, [client]);
  const signOut = useCallback((o?: { federated?: boolean; postLogoutRedirectUri?: string }) => client.signOut(o), [client]);
  const getAccessToken = useCallback((o?: { forceRefresh?: boolean }) => client.getAccessToken(o), [client]);
  const value = useMemo(() => ({ ...state, client, signIn, signInWithPopup, signOut, getAccessToken }), [state, client, signIn, signInWithPopup, signOut, getAccessToken]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useIdentvia(): IdentviaContextValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('useIdentvia() must be used inside <IdentviaProvider>.');
  return v;
}

/** Same as useIdentvia() but returns null outside a provider (used by the button). */
export function useOptionalIdentvia(): IdentviaContextValue | null { return useContext(Ctx); }

export function SignedIn({ children }: { children?: ReactNode }) {
  const { isAuthenticated, isLoading } = useIdentvia();
  return !isLoading && isAuthenticated ? <>{children}</> : null;
}

export function SignedOut({ children }: { children?: ReactNode }) {
  const { isAuthenticated, isLoading } = useIdentvia();
  return !isLoading && !isAuthenticated ? <>{children}</> : null;
}
