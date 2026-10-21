/** Base class for every error the SDK throws. `code` is stable and safe to branch on. */
export class IdentviaError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = 'IdentviaError';
    this.code = code;
    if (options && 'cause' in options) (this as { cause?: unknown }).cause = options.cause;
  }
}

/** Misconfiguration (bad issuer, insecure redirect URI, secret in a public client...). Fix your code. */
export class ConfigurationError extends IdentviaError {
  constructor(message: string) { super('configuration_error', message); this.name = 'ConfigurationError'; }
}

/** The callback could not be tied to a sign-in this app started (state missing/unknown/reused, iss mismatch). Start again. */
export class InvalidStateError extends IdentviaError {
  constructor(message: string) { super('invalid_state', message); this.name = 'InvalidStateError'; }
}

/** Identvia returned an OAuth error to the redirect URI (e.g. the user pressed Cancel: `access_denied`). */
export class AuthorizationError extends IdentviaError {
  readonly error: string;
  readonly errorDescription: string | undefined;
  readonly returnTo: string | undefined;
  constructor(error: string, description?: string, returnTo?: string) {
    super(error, description ? `${error}: ${description}` : error);
    this.name = 'AuthorizationError';
    this.error = error;
    this.errorDescription = description;
    this.returnTo = returnTo;
  }
}

/** The token endpoint (or another OAuth endpoint) answered with an error. */
export class TokenError extends IdentviaError {
  readonly error: string;
  readonly errorDescription: string | undefined;
  readonly status: number;
  constructor(error: string, description: string | undefined, status: number) {
    super(error, description ? `${error}: ${description}` : error);
    this.name = 'TokenError';
    this.error = error;
    this.errorDescription = description;
    this.status = status;
  }
}

/** An ID token (or other signed response) failed validation. Never trust its contents. */
export class ValidationError extends IdentviaError {
  constructor(message: string, options?: { cause?: unknown }) { super('validation_error', message, options); this.name = 'ValidationError'; }
}

/** The connected Identvia server does not advertise a feature (e.g. CIBA on servers older than 2026-10-21_5). */
export class UnsupportedError extends IdentviaError {
  constructor(message: string) { super('unsupported', message); this.name = 'UnsupportedError'; }
}

/** Network failure or a non-JSON / unexpected HTTP response. */
export class HttpError extends IdentviaError {
  readonly status: number | undefined;
  constructor(message: string, status?: number, options?: { cause?: unknown }) { super('http_error', message, options); this.name = 'HttpError'; this.status = status; }
}
