/** Anything shaped like Web Storage. Async implementations (e.g. IndexedDB wrappers) are fine too. */
export interface KeyValueStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

export class MemoryStorage implements KeyValueStorage {
  private m = new Map<string, string>();
  getItem(k: string) { return this.m.has(k) ? this.m.get(k)! : null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
}

/**
 * Where to keep tokens:
 *  - 'memory' (default): safest against XSS persistence; the user signs in again after a reload unless
 *    you also use refresh tokens with 'session'/'local'.
 *  - 'session': survives reloads, per tab.
 *  - 'local': shared across tabs, survives restarts. Only with a strict CSP; any XSS can read it.
 *  - a custom KeyValueStorage.
 */
export type TokenStorageOption = 'memory' | 'session' | 'local' | KeyValueStorage;

export function resolveStorage(opt: TokenStorageOption | undefined): KeyValueStorage {
  if (opt === undefined || opt === 'memory') return new MemoryStorage();
  if (opt === 'session' || opt === 'local') {
    const g = globalThis as { sessionStorage?: Storage; localStorage?: Storage };
    const s = opt === 'session' ? g.sessionStorage : g.localStorage;
    if (!s) return new MemoryStorage();
    return s;
  }
  return opt;
}

export function transactionStorage(): KeyValueStorage {
  const g = globalThis as { sessionStorage?: Storage };
  return g.sessionStorage ?? new MemoryStorage();
}
