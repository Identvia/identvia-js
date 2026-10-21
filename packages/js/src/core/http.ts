import { HttpError, TokenError } from './errors.js';

export type FetchLike = (input: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{
  ok: boolean; status: number; headers: { get(name: string): string | null }; text(): Promise<string>;
}>;

export function defaultFetch(): FetchLike {
  const f = (globalThis as { fetch?: unknown }).fetch;
  if (typeof f !== 'function') throw new HttpError('fetch is not available; pass `fetch` in the options.');
  return f.bind(globalThis) as FetchLike;
}

const MAX_BODY = 256 * 1024;

export async function requestJson(fetchFn: FetchLike, url: string, init: Parameters<FetchLike>[1] = {}, timeoutMs = 15000): Promise<{ status: number; data: Record<string, unknown>; headers: { get(n: string): string | null } }> {
  const ctrl = typeof AbortController === 'function' ? new AbortController() : undefined;
  const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : undefined;
  let res;
  try {
    res = await fetchFn(url, { ...init, ...(ctrl ? { signal: ctrl.signal } : {}) });
  } catch (e) {
    throw new HttpError(`Request to ${new URL(url).origin} failed.`, undefined, { cause: e });
  } finally {
    if (timer) clearTimeout(timer);
  }
  const text = await res.text();
  if (text.length > MAX_BODY) throw new HttpError('Response too large.', res.status);
  let data: unknown = {};
  if (text !== '') {
    try { data = JSON.parse(text); } catch { throw new HttpError(`Expected JSON from ${new URL(url).pathname} (HTTP ${res.status}).`, res.status); }
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) throw new HttpError('Expected a JSON object.', res.status);
  return { status: res.status, data: data as Record<string, unknown>, headers: res.headers };
}

/** POST application/x-www-form-urlencoded; turns OAuth error bodies into TokenError. */
export async function postForm(fetchFn: FetchLike, url: string, form: Record<string, string | undefined>, headers: Record<string, string> = {}, expectBody = true): Promise<Record<string, unknown>> {
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(form)) if (v !== undefined) body.set(k, v);
  const { status, data } = await requestJson(fetchFn, url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', ...headers },
    body: body.toString(),
  });
  if (status < 200 || status >= 300) {
    throw new TokenError(typeof data.error === 'string' ? data.error : 'http_error', typeof data.error_description === 'string' ? data.error_description : undefined, status);
  }
  return expectBody ? data : {};
}
