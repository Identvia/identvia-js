import type { AuthorizationDetail } from '../core/tokens.js';

/**
 * Builds an `agent_task` authorization detail (RFC 9396) describing one task an agent wants to do.
 * Identvia shows it on the consent screen and carries it into the token. Requires server 2026-10-21_5+.
 */
export function agentTask(d: { description: string; actions?: string[]; locations?: string[]; [k: string]: unknown }): AuthorizationDetail {
  if (!d || typeof d.description !== 'string' || d.description.trim() === '') throw new TypeError('agentTask needs a description.');
  return { type: 'agent_task', ...d };
}
