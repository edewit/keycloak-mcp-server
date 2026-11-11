/**
 * The browser side of the BFF (/bff): same-origin fetches with the session cookie, never a token. Every call carries
 * X-Requested-With: JavaScript, which makes the server answer 499 instead of redirecting to the identity provider
 * when there is no session, and which the server demands on every request that changes something (CSRF).
 */
export const BFF = '/bff';

export interface Idp {
  alias: string;
  displayName: string;
  loginPath: string;
}

export interface Me {
  authenticated: boolean;
  logoutPath: string;
  /** The providers of the login page (hidden ones never) */
  idps: Idp[];
  /** The provider named by ?idp= (the return from a logout), if it is on the page; offered first. */
  suggestedIdp?: string;
  idp?: string;
  subject?: string;
  username?: string;
  name?: string;
  email?: string;
  realm?: string;
  issuer?: string;
  roles?: string[];
  adminRole?: string;
  /** True when the session holds kc-mcp.admin.role (operator). */
  admin?: boolean;
  /** True when the session holds kc-mcp.ui.viewer-role (read-only), if configured. */
  viewer?: boolean;
  viewerRole?: string;
  /** BFF-enforced capabilities; the UI only hides. */
  capabilities?: string[];
  sessionExpiresAt?: string;
}

/** Capability strings from GET /bff/me. */
export const Cap = {
  systemsRead: 'systems:read',
  systemsWrite: 'systems:write',
  secretsRead: 'secrets:read',
  storageRead: 'storage:read',
} as const;

export function hasCapability(me: Me | null | undefined, capability: string): boolean {
  return !!me?.capabilities?.includes(capability);
}

/** One Keycloak system as returned by GET /bff/api/systems[/{alias}]. */
export interface System {
  alias: string;
  displayName?: string;
  description?: string;
  url: string;
  issuer?: string;
  authRealm: string;
  grantType: string;
  clientAuth: string;
  clientId?: string;
  /** Masked as "***", or a vault: reference. */
  clientSecret?: string;
  username?: string;
  password?: string;
  defaultRealm?: string;
  allowedRealms: string[];
  /** Issuers besides this Keycloak whose caller tokens may be used here. */
  trustedIssuers?: string[];
  version?: string;
  /** System-level preset name when set. */
  preset?: string;
  /** Named presets defined on this system (keys are preset names). */
  presets?: Record<string, unknown>;
  /** Per-realm settings keyed by realm name (embedded on the system GET). */
  realms?: Record<string, Omit<SystemRealm, 'name' | 'system' | 'entry'>>;
  access?: Record<string, unknown>;
  tools?: Record<string, unknown>;
  source?: string;
  /** True when the admin/BFF API can replace this system (mutable repository). */
  writable?: boolean;
  createdAt?: string;
  updatedAt?: string;
  signingKey?: {
    algorithm?: string;
    kid?: string;
    vault?: string;
    configured?: boolean;
    jwksPath?: string;
    jwksUrl?: string;
  };
  entries?: string[];
}

/** One realm's stored settings as returned by GET /bff/api/systems/{alias}/realms[/{realm}]. */
export interface SystemRealm {
  name: string;
  system: string;
  realmId?: string;
  displayName?: string;
  description?: string;
  preset?: string;
  access?: Record<string, unknown>;
  tools?: Record<string, unknown>;
  entry?: string;
}

export interface SystemRealmsList {
  realms: SystemRealm[];
}

/** Body for PUT /bff/api/systems/{alias}/realms/{realm}. */
export type SystemRealmSave = {
  realmId?: string;
  displayName?: string;
  description?: string;
  preset?: string;
  access?: Record<string, unknown>;
  tools?: Record<string, unknown>;
};

export interface SystemsList {
  systems: System[];
  /** False when there is no mutable repository or registration is closed. */
  canCreate?: boolean;
  mutableSource?: string;
  canCreateHint?: string;
}

/** Body for PUT /bff/api/systems/{alias} (omit secrets to keep stored values). */
export type SystemSave = {
  url: string;
  displayName?: string;
  description?: string;
  issuer?: string;
  authRealm?: string;
  grantType?: string;
  clientAuth?: string;
  clientId?: string;
  clientSecret?: string;
  defaultRealm?: string;
  allowedRealms?: string[];
  trustedIssuers?: string[];
  version?: string;
  signingKey?: string;
};

export class BffError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }

  /** 499: the session is gone (expired, signed out elsewhere); 401 is the server's own fallback. */
  get sessionLost(): boolean {
    return this.status === 499 || this.status === 401;
  }
}

async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('X-Requested-With', 'JavaScript');
  headers.set('Accept', 'application/json');
  const response = await fetch(`${BFF}${path}`, { ...init, headers, credentials: 'same-origin' });
  if (response.ok) {
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }
  let code = `http_${response.status}`;
  let message = response.statusText || `HTTP ${response.status}`;
  try {
    const body = (await response.json()) as { error?: string; message?: string };
    code = body.error ?? code;
    message = body.message ?? message;
  } catch {
    // no JSON body (499 has none)
  }
  throw new BffError(response.status, code, message);
}

/**
 * Who is signed in. A cookie whose session is gone (expired, signed out at the provider) makes the first call answer
 * 499 and clears the cookie; the second call is anonymous and lists the identity providers.
 */
export async function me(idp?: string): Promise<Me> {
  // `idp` names the provider the page was opened for (a tenant's link, the return from a logout)
  const path = idp ? `/me?idp=${encodeURIComponent(idp)}` : '/me';
  try {
    return await call<Me>(path);
  } catch (e) {
    if (e instanceof BffError && e.sessionLost) {
      return call<Me>(path);
    }
    throw e;
  }
}

/** Outcome of an explicit session check (POST /bff/check-session). */
export interface SessionCheck {
  active: true;
  checkedAt: string;
  sessionExpiresAt?: string;
  cookieExpiresAt?: string;
  accessTokenExpiresAt?: string;
}

/**
 * Is the session still alive at the identity provider? The server redeems the refresh token there, which also counts
 * as activity (the SSO idle timeout moves) and renews the cookie. Resolves false when the session ended elsewhere
 * (logout in another app or the account console, an administrator, the idle timeout): the UI must reset then.
 */
export async function checkSession(): Promise<SessionCheck | false> {
  try {
    return await call<SessionCheck>('/check-session', { method: 'POST' });
  } catch (e) {
    if (e instanceof BffError && e.sessionLost) {
      return false;
    }
    throw e;
  }
}

/** All known systems (GET /bff/api/systems). */
export const listSystems = (): Promise<SystemsList> => call<SystemsList>('/api/systems');

/** @deprecated use listSystems */
export const systems = (): Promise<SystemsList> => listSystems();

/** One system (GET /bff/api/systems/{alias}). */
export const getSystem = (alias: string): Promise<System> =>
  call<System>(`/api/systems/${encodeURIComponent(alias)}`);

/** Replace a mutable system (PUT /bff/api/systems/{alias}). */
export const saveSystem = (alias: string, body: SystemSave): Promise<System> =>
  call<System>(`/api/systems/${encodeURIComponent(alias)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

/** Remove a mutable system (DELETE /bff/api/systems/{alias}). Keys stay in the vault. */
export const deleteSystem = (alias: string): Promise<void> =>
  call<void>(`/api/systems/${encodeURIComponent(alias)}`, { method: 'DELETE' });

/** Rotate the system's signing key (POST /bff/api/systems/{alias}/signing-key). */
export const rotateSigningKey = (alias: string): Promise<System> =>
  call<System>(`/api/systems/${encodeURIComponent(alias)}/signing-key`, { method: 'POST' });

/** Realm settings kept for a system (GET /bff/api/systems/{alias}/realms). */
export const listSystemRealms = (alias: string): Promise<SystemRealmsList> =>
  call<SystemRealmsList>(`/api/systems/${encodeURIComponent(alias)}/realms`);

/** One realm's settings (GET /bff/api/systems/{alias}/realms/{realm}). */
export const getSystemRealm = (alias: string, realm: string): Promise<SystemRealm> =>
  call<SystemRealm>(
    `/api/systems/${encodeURIComponent(alias)}/realms/${encodeURIComponent(realm)}`,
  );

/** Add or replace realm settings (PUT /bff/api/systems/{alias}/realms/{realm}). */
export const saveSystemRealm = (
  alias: string,
  realm: string,
  body: SystemRealmSave,
): Promise<SystemRealm> =>
  call<SystemRealm>(
    `/api/systems/${encodeURIComponent(alias)}/realms/${encodeURIComponent(realm)}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );

/** Remove realm settings so the system's settings apply again. */
export const deleteSystemRealm = (alias: string, realm: string): Promise<void> =>
  call<void>(`/api/systems/${encodeURIComponent(alias)}/realms/${encodeURIComponent(realm)}`, {
    method: 'DELETE',
  });

/** Full-page navigations: the code flow and the RP-initiated logout are redirects, not fetches. */
export const login = (idp: Idp): void => {
  window.location.assign(idp.loginPath);
};
export const logout = (me: Me): void => {
  window.location.assign(me.logoutPath);
};
