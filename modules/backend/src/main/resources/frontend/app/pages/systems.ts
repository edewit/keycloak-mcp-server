import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { BffError, listSystems, type System } from '../bff.js';
import { newSystemHref, systemHref } from '../router.js';
import { sessionCanWrite, sessionContext, type SessionState } from '../session-context.js';

/** Systems list via GET /bff/api/systems; each row is a Keycloak cluster/environment. */
@customElement('kc-mcp-systems-page')
export class SystemsPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    h2 {
      font-size: 1rem;
      margin: 0 0 0.5rem;
    }
    p {
      margin: 0 0 0.75rem;
      color: var(--muted, #656d76);
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      margin-bottom: 0.75rem;
    }
    button,
    a.btn {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      border: 1px solid var(--accent, #1f6feb);
      background: var(--accent, #1f6feb);
      color: #fff;
      cursor: pointer;
      text-decoration: none;
      font-weight: 500;
      display: inline-block;
    }
    button.secondary {
      background: transparent;
      color: var(--fg, inherit);
      border-color: var(--border, #8b949e);
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
    .error {
      color: var(--error, #cf222e);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th,
    td {
      text-align: left;
      padding: 0.55rem 0.65rem;
      border-bottom: 1px solid var(--border, #d0d7de);
      vertical-align: top;
    }
    th {
      color: var(--muted, #656d76);
      font-weight: 600;
    }
    a {
      color: var(--accent, #1f6feb);
      text-decoration: none;
      font-weight: 600;
    }
    a:hover {
      text-decoration: underline;
    }
    .muted {
      color: var(--muted, #656d76);
    }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      border: 1px solid var(--border, #d0d7de);
      color: var(--muted, #656d76);
    }
  `;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private items: System[] = [];

  @state()
  private canCreate = false;

  @state()
  private canCreateHint: string | null = null;

  @state()
  private error: string | null = null;

  @state()
  private busy = false;

  private get canWrite(): boolean {
    return sessionCanWrite(this.session);
  }

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  private async load(): Promise<void> {
    this.busy = true;
    this.error = null;
    try {
      const data = await listSystems();
      const canWrite = this.canWrite;
      this.items = data.systems ?? [];
      this.canCreate = !!data.canCreate && canWrite;
      this.canCreateHint = canWrite
        ? (data.canCreateHint ?? null)
        : 'Sign in with the operator role (kc-mcp.admin.role) to register or change systems.';
    } catch (e) {
      this.items = [];
      this.canCreate = false;
      this.canCreateHint = null;
      if (e instanceof BffError) {
        this.error = `${e.status} ${e.code}: ${e.message}`;
        if (e.sessionLost) {
          this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
        }
      } else {
        this.error = e instanceof Error ? e.message : String(e);
      }
    } finally {
      this.busy = false;
    }
  }

  private realmsSummary(s: System): string {
    const allowed = s.allowedRealms ?? [];
    if (allowed.length === 0) {
      return s.defaultRealm ? `all (default ${s.defaultRealm})` : 'all realms';
    }
    if (allowed.length <= 3) {
      return allowed
        .map((r) => (r === s.defaultRealm ? `${r}*` : r))
        .join(', ');
    }
    return `${allowed.length} realms`;
  }

  render() {
    return html`
      <h2>Systems</h2>
      <p>
        Keycloak clusters and environments known to this server. Each system has a front-door URL and zero or more
        managed realms (all realms, or an explicit allowlist).
      </p>
      <div class="row">
        ${this.canCreate
          ? html`<a class="btn" href=${newSystemHref()}>Add system</a>`
          : nothing}
        <button class="secondary" type="button" ?disabled=${this.busy} @click=${() => this.load()}>
          Refresh
        </button>
      </div>
      ${!this.canCreate && this.canCreateHint && !this.error
        ? html`<p class="muted">${this.canCreateHint}</p>`
        : nothing}
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${!this.error && !this.busy && this.items.length === 0
        ? html`<p class="muted">No systems registered.</p>`
        : nothing}
      ${this.items.length
        ? html`<table>
            <thead>
              <tr>
                <th>Alias</th>
                <th>URL</th>
                <th>Realms</th>
                <th>Source</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${this.items.map((s) => this.renderRow(s))}
            </tbody>
          </table>`
        : nothing}
    `;
  }

  private renderRow(s: System) {
    const href = systemHref(s.alias);
    const realmsHref = systemHref(s.alias, 'realms');
    return html`
      <tr>
        <td>
          <a href=${href}>${s.displayName || s.alias}</a>
          ${s.displayName ? html`<div class="muted"><code>${s.alias}</code></div>` : nothing}
        </td>
        <td><code>${s.url}</code></td>
        <td>
          <a href=${realmsHref}>${this.realmsSummary(s)}</a>
        </td>
        <td>
          <span class="badge">${s.source ?? '—'}</span>
          ${s.writable === false ? html` <span class="badge">read-only</span>` : nothing}
        </td>
        <td
          ><a href=${href}
            >${s.writable === false || !this.canWrite ? 'View' : 'Open'}</a
          ></td
        >
      </tr>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-systems-page': SystemsPage;
  }
}
