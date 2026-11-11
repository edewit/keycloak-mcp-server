import { createContext } from '@lit/context';
import { Cap, hasCapability, type Me } from './bff.js';

/** Session provided by {@link KcMcpApp} for the shell and pages. */
export type SessionState = {
  me: Me | null;
  lastCheck: { at: Date; ok: boolean } | null;
};

export const sessionContext = createContext<SessionState>('kc-mcp-session');

export function sessionCanWrite(session: SessionState | undefined): boolean {
  return hasCapability(session?.me, Cap.systemsWrite);
}
