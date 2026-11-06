import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { BffError, checkSession, login, logout, me, systems, type Me, type SessionCheck } from './bff.js';

/**
 * The bootstrap of the management UI: who is signed in, sign-in buttons (one per identity provider), sign-out,
 * and one call of the BFF API to prove the session works end to end. Everything else is for the pages to come.
 */
@customElement('kc-mcp-app')
export class KcMcpApp extends LitElement {
  static styles = css`
    :host {
      display: block;
      font: 15px/1.5 system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
      color: #1f2328;
      background: #f6f8fa;
      min-height: 100vh;
    }
    @media (prefers-color-scheme: dark) {
      :host {
        color: #e6edf3;
        background: #0d1117;
      }
      .card {
        background: #161b22;
        border-color: #30363d;
      }
      pre {
        background: #0d1117;
      }
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.75rem 1.5rem;
      border-bottom: 1px solid #d0d7de55;
    }
    h1 {
      font-size: 1.1rem;
      margin: 0;
    }
    main {
      max-width: 56rem;
      margin: 0 auto;
      padding: 1.5rem;
      display: grid;
      gap: 1rem;
    }
    .card {
      background: #fff;
      border: 1px solid #d0d7de;
      border-radius: 8px;
      padding: 1rem 1.25rem;
    }
    h2 {
      font-size: 1rem;
      margin: 0 0 0.5rem;
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      border: 1px solid #1f6feb;
      background: #1f6feb;
      color: #fff;
      cursor: pointer;
    }
    button.secondary {
      background: transparent;
      color: inherit;
      border-color: #8b949e;
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    dl {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.25rem 1rem;
      margin: 0.5rem 0 0;
    }
    dt {
      color: #656d76;
    }
    dd {
      margin: 0;
      overflow-wrap: anywhere;
    }
    pre {
      background: #f6f8fa;
      padding: 0.75rem;
      border-radius: 6px;
      overflow: auto;
      font-size: 0.85rem;
      margin: 0.5rem 0 0;
    }
    .error {
      color: #cf222e;
    }
    .muted {
      color: #656d76;
    }
  `;

  @state() private session: Me | null = null;
  @state() private sessionError: string | null = null;
  @state() private apiResult: string | null = null;
  @state() private apiError: string | null = null;
  @state() private busy = false;
  @state() private lastCheck: { at: Date; ok: boolean } | null = null;
  /** The provider to offer first: ?idp= in the address (a tenant's link, a logout's return), else this tab's last session's. */
  private suggestedIdp: string | undefined;
  private checking = false;
  private readonly onVisible = () => {
    if (document.visibilityState === 'visible' && this.session?.authenticated && !this.checking) {
      void this.checkSession();
    }
  };

  connectedCallback(): void {
    super.connectedCallback();
    // /ui/?idp=<alias> names the provider to offer first (a tenant's link, the return from a logout); Quarkus adds
    // ?state=... to the logout's return, which the address bar need not keep
    const url = new URL(window.location.href);
    this.suggestedIdp = url.searchParams.get('idp') ?? undefined;
    if (url.searchParams.has('state')) {
      url.searchParams.delete('state');
      window.history.replaceState(null, '', url.toString());
    }
    void this.refresh();
    this.trackActivity();
  }

  disconnectedCallback(): void {
    document.removeEventListener('visibilitychange', this.onVisible);
    window.removeEventListener('focus', this.onVisible);
    super.disconnectedCallback();
  }

  /**
   * Whenever the user comes back to this tab (Page Visibility API) while signed in, ask the server whether the
   * session still exists at the identity provider: activity tracking instead of a rolling cookie. The server renews
   * the tokens and the cookie on success and answers 401 when the session ended elsewhere (logout in another app or
   * the account console, an administrator, the idle timeout); the page then shows the sign-in buttons again.
   */
  private trackActivity(): void {
    document.addEventListener('visibilitychange', this.onVisible);
    // a switch between browser windows changes the focus, not the visibility
    window.addEventListener('focus', this.onVisible);
  }

  private async checkSession(): Promise<void> {
    this.checking = true;
    try {
      const check: SessionCheck | false = await checkSession();
      this.lastCheck = { at: new Date(), ok: check !== false };
      if (check === false) {
        this.apiResult = null;
        this.apiError = null;
      }
      await this.refresh();
    } catch (e) {
      this.sessionError = e instanceof Error ? e.message : String(e);
    } finally {
      this.checking = false;
    }
  }

  private async refresh(): Promise<void> {
    try {
      this.session = await me(this.suggestedIdp);
      if (this.session.authenticated && this.session.idp) {
        // when this session ends elsewhere, offer its provider first
        this.suggestedIdp = this.session.idp;
      }
      this.sessionError = null;
    } catch (e) {
      this.session = null;
      this.sessionError = e instanceof Error ? e.message : String(e);
    }
  }

  private async callApi(): Promise<void> {
    this.busy = true;
    this.apiResult = null;
    this.apiError = null;
    try {
      this.apiResult = JSON.stringify(await systems(), null, 2);
    } catch (e) {
      if (e instanceof BffError) {
        this.apiError = `${e.status} ${e.code}: ${e.message}`;
        if (e.sessionLost) {
          await this.refresh();
        }
      } else {
        this.apiError = e instanceof Error ? e.message : String(e);
      }
    } finally {
      this.busy = false;
    }
  }

  render() {
    const s = this.session;
    return html`
      <header>
        <h1>Keycloak MCP Server</h1>
        ${s?.authenticated
          ? html`<div class="row">
              <span>${s.name ?? s.username}</span>
              <button class="secondary" @click=${() => logout(s)}>Sign out</button>
            </div>`
          : nothing}
      </header>
      <main>
        ${this.renderSession()}
        ${s?.authenticated ? this.renderApiTest() : nothing}
      </main>
    `;
  }

  private renderSession() {
    const s = this.session;
    if (this.sessionError) {
      return html`<section class="card">
        <h2>Session</h2>
        <p class="error">${this.sessionError}</p>
        <button class="secondary" @click=${() => this.refresh()}>Retry</button>
      </section>`;
    }
    if (!s) {
      return html`<section class="card"><p class="muted">Loading…</p></section>`;
    }
    if (!s.authenticated) {
      // the provider the page was opened for (or this tab's last session used) comes first
      const suggested = s.suggestedIdp ?? this.suggestedIdp;
      const last = s.idps.find((idp) => idp.alias === suggested);
      const others = s.idps.filter((idp) => idp !== last);
      return html`<section class="card">
        <h2>Not signed in</h2>
        <p class="muted">The server signs you in at the identity provider and keeps the session on its side.</p>
        <div class="row">
          ${last
            ? html`<button @click=${() => login(last)}>${last.displayName}</button>
                ${others.length ? html`<span class="muted">or</span>` : nothing}`
            : nothing}
          ${others.map(
            (idp) => html`<button class=${last ? 'secondary' : ''} @click=${() => login(idp)}>${idp.displayName}</button>`,
          )}
        </div>
      </section>`;
    }
    return html`<section class="card">
      <h2>Signed in</h2>
      <dl>
        <dt>User</dt>
        <dd>${s.username} ${s.email ? html`<span class="muted">(${s.email})</span>` : nothing}</dd>
        <dt>Identity provider</dt>
        <dd>${s.idp} <span class="muted">${s.issuer}</span></dd>
        <dt>Roles</dt>
        <dd>${s.roles?.join(', ') || html`<span class="muted">none</span>`}</dd>
        <dt>Management role</dt>
        <dd>${s.adminRole} ${s.admin ? '✓' : html`<span class="error">missing</span>`}</dd>
        <dt>Session expires</dt>
        <dd>${s.sessionExpiresAt ? new Date(s.sessionExpiresAt).toLocaleString() : '–'}</dd>
        <dt>Last session check</dt>
        <dd>
          ${this.lastCheck
            ? html`${this.lastCheck.at.toLocaleTimeString()} ${this.lastCheck.ok ? '✓' : html`<span class="error">session ended</span>`}`
            : html`<span class="muted">when this tab becomes visible again</span>`}
          <button class="secondary" @click=${() => this.checkSession()}>Check now</button>
        </dd>
      </dl>
    </section>`;
  }

  private renderApiTest() {
    return html`<section class="card">
      <h2>BFF API test</h2>
      <p class="muted">
        <code>GET /bff/api/systems</code> runs with the session cookie; the server checks the management role.
      </p>
      <button ?disabled=${this.busy} @click=${() => this.callApi()}>Call the API</button>
      ${this.apiError ? html`<p class="error">${this.apiError}</p>` : nothing}
      ${this.apiResult ? html`<pre>${this.apiResult}</pre>` : nothing}
    </section>`;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-app': KcMcpApp;
  }
}
