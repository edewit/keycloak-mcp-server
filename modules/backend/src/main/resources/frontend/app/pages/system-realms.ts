import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import {
  BffError,
  Cap,
  hasCapability,
  listSystemRealms,
  me,
  saveSystemRealm,
  type System,
  type SystemRealm,
} from '../bff.js';
import { realmHref, systemHref } from '../router.js';

type Row = {
  realm: string;
  displayName?: string;
  preset?: string;
  entry: string;
  isDefault: boolean;
  hasSettings: boolean;
  onAllowlist: boolean;
  outsideAllowlist: boolean;
  inherits: boolean;
  policyBadge: boolean;
};

/** Realms for one system: allowlist merged with stored realm settings from the realm API. */
@customElement('kc-mcp-system-realms')
export class SystemRealms extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    .lead {
      margin: 0 0 0.75rem;
      color: var(--muted, #656d76);
      font-size: 0.9rem;
    }
    .lead a {
      color: var(--accent, #1f6feb);
      font-weight: 600;
      text-decoration: none;
    }
    .lead a:hover {
      text-decoration: underline;
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
    code {
      font-size: 0.85em;
      overflow-wrap: anywhere;
    }
    .badge {
      display: inline-block;
      font-size: 0.75rem;
      padding: 0.1rem 0.4rem;
      border-radius: 4px;
      border: 1px solid var(--border, #d0d7de);
      color: var(--muted, #656d76);
      margin-left: 0.35rem;
    }
    .muted {
      color: var(--muted, #656d76);
    }
    .error {
      color: var(--error, #cf222e);
      margin: 0 0 0.75rem;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
      margin: 0.75rem 0 0;
    }
    input {
      font: inherit;
      color: var(--fg, inherit);
      background: var(--bg, #f6f8fa);
      border: 1px solid var(--border, #d0d7de);
      border-radius: 6px;
      padding: 0.35rem 0.55rem;
    }
    button,
    a.btn {
      font: inherit;
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      border: 1px solid var(--accent, #1f6feb);
      background: var(--accent, #1f6feb);
      color: #fff;
      cursor: pointer;
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 500;
    }
    button.secondary,
    a.btn.secondary {
      background: transparent;
      color: var(--fg, inherit);
      border-color: var(--border, #8b949e);
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
    a {
      color: var(--accent, #1f6feb);
      text-decoration: none;
      font-weight: 600;
    }
    a:hover {
      text-decoration: underline;
    }
    .copy {
      margin-left: 0.35rem;
      padding: 0.15rem 0.45rem;
      font-size: 0.75rem;
    }
  `;

  @property({ attribute: false })
  system: System | null = null;

  @state()
  private realms: SystemRealm[] = [];

  @state()
  private busy = false;

  @state()
  private error: string | null = null;

  @state()
  private canWrite = false;

  @state()
  private addName = '';

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  protected updated(changed: Map<string, unknown>): void {
    if (changed.has('system') && this.system) {
      void this.load();
    }
  }

  private systemRoot(s: System): string {
    return s.entries?.[0] ?? `/mcp/systems/${s.alias}`;
  }

  private realmEntry(s: System, realm: string, stored?: SystemRealm): string {
    if (stored?.entry) {
      return stored.entry;
    }
    const root = this.systemRoot(s);
    return (s.entries ?? []).find((e) => e === `${root}/${realm}`) ?? `${root}/${realm}`;
  }

  private async load(): Promise<void> {
    if (!this.system) {
      this.realms = [];
      return;
    }
    this.busy = true;
    this.error = null;
    try {
      const session = await me();
      this.canWrite = hasCapability(session, Cap.systemsWrite);
      const list = await listSystemRealms(this.system.alias);
      this.realms = list.realms ?? [];
    } catch (e) {
      this.realms = [];
      this.report(e);
    } finally {
      this.busy = false;
    }
  }

  private rows(s: System): Row[] {
    const allowed = s.allowedRealms ?? [];
    const byName = new Map(this.realms.map((r) => [r.name, r]));
    const names = new Set<string>([...allowed, ...byName.keys()]);
    const sorted = [...names].sort((a, b) => a.localeCompare(b));
    return sorted.map((realm) => {
      const stored = byName.get(realm);
      const onAllowlist = allowed.length === 0 || allowed.includes(realm);
      const hasSettings = !!stored;
      return {
        realm,
        displayName: stored?.displayName,
        preset: stored?.preset,
        entry: this.realmEntry(s, realm, stored),
        isDefault: s.defaultRealm === realm,
        hasSettings,
        onAllowlist,
        outsideAllowlist: allowed.length > 0 && !allowed.includes(realm),
        inherits: !hasSettings,
        policyBadge: !!(stored?.access || stored?.tools),
      };
    });
  }

  private async addSettings(realm: string): Promise<void> {
    if (!this.system || !this.canWrite || !this.system.writable) {
      return;
    }
    this.busy = true;
    this.error = null;
    try {
      await saveSystemRealm(this.system.alias, realm, { displayName: realm });
      history.pushState({}, '', realmHref(this.system.alias, realm));
      window.dispatchEvent(new PopStateEvent('popstate'));
    } catch (e) {
      this.report(e);
      this.busy = false;
    }
  }

  private async addNamed(event: Event): Promise<void> {
    event.preventDefault();
    const name = this.addName.trim();
    if (!name || !this.system) {
      return;
    }
    await this.addSettings(name);
  }

  private async copyEntry(entry: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(entry);
    } catch {
      // ignore clipboard failures
    }
  }

  private report(e: unknown): void {
    if (e instanceof BffError) {
      this.error = `${e.status} ${e.code}: ${e.message}`;
      if (e.sessionLost) {
        this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
      }
    } else {
      this.error = e instanceof Error ? e.message : String(e);
    }
  }

  render() {
    const s = this.system;
    if (!s) {
      return html`<p class="muted">No system loaded.</p>`;
    }
    const root = this.systemRoot(s);
    const allowed = s.allowedRealms ?? [];
    const writable = this.canWrite && !!s.writable;
    const rows = this.rows(s);

    return html`
      <p class="lead">
        Managed realms for this Keycloak cluster. The allowlist and default realm are edited under
        <a href=${systemHref(s.alias, 'settings')}>Settings</a>; per-realm labels and presets live here.
      </p>
      ${allowed.length === 0
        ? html`<p class="lead muted">
            No allowlist — every realm on this Keycloak is in scope for tools (subject to other policy). System entry:
            <code>${root}</code>
          </p>`
        : html`<p class="lead muted">System entry (any allowed realm): <code>${root}</code></p>`}
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${this.busy && rows.length === 0 ? html`<p class="muted">Loading…</p>` : nothing}
      <table>
        <thead>
          <tr>
            <th>Realm</th>
            <th>Settings</th>
            <th>MCP entry</th>
            ${writable ? html`<th></th>` : nothing}
          </tr>
        </thead>
        <tbody>
          ${rows.length === 0
            ? html`<tr>
                <td colspan=${writable ? 4 : 3} class="muted">
                  No allowlist entries and no stored realm settings yet.
                </td>
              </tr>`
            : rows.map(
                (row) => html`
                  <tr>
                    <td>
                      ${row.hasSettings
                        ? html`<a href=${realmHref(s.alias, row.realm)}
                            >${row.displayName || row.realm}</a
                          >`
                        : html`${row.displayName || row.realm}`}
                      ${row.displayName && row.displayName !== row.realm
                        ? html`<div class="muted"><code>${row.realm}</code></div>`
                        : nothing}
                      ${row.isDefault ? html`<span class="badge">default</span>` : nothing}
                      ${row.outsideAllowlist
                        ? html`<span class="badge">outside allowlist</span>`
                        : nothing}
                    </td>
                    <td>
                      ${row.inherits
                        ? html`<span class="muted">inherits system</span>`
                        : html`${row.preset
                            ? html`<span class="badge">preset ${row.preset}</span>`
                            : nothing}
                          ${row.policyBadge
                            ? html`<span class="badge">own access/tools</span>`
                            : html`<span class="muted">labels only</span>`}`}
                    </td>
                    <td>
                      <code>${row.entry}</code>
                      <button
                        class="secondary copy"
                        type="button"
                        title="Copy MCP entry"
                        @click=${() => this.copyEntry(row.entry)}
                      >
                        Copy
                      </button>
                    </td>
                    ${writable
                      ? html`<td>
                          ${row.hasSettings
                            ? html`<a class="btn secondary" href=${realmHref(s.alias, row.realm)}>Open</a>`
                            : html`<button
                                class="secondary"
                                type="button"
                                ?disabled=${this.busy}
                                @click=${() => this.addSettings(row.realm)}
                              >
                                Add settings
                              </button>`}
                        </td>`
                      : nothing}
                  </tr>
                `,
              )}
        </tbody>
      </table>
      ${s.defaultRealm && allowed.length === 0
        ? html`<p class="lead muted">
            Default realm for tools when <code>realm</code> is omitted:
            <code>${s.defaultRealm}</code>
          </p>`
        : nothing}
      ${writable
        ? html`<form class="row" @submit=${(e: Event) => this.addNamed(e)}>
            <input
              .value=${this.addName}
              ?disabled=${this.busy}
              @input=${(e: Event) => {
                this.addName = (e.target as HTMLInputElement).value;
              }}
              placeholder="realm name"
              aria-label="Realm name for new settings"
            />
            <button type="submit" ?disabled=${this.busy || !this.addName.trim()}>Add settings</button>
            <span class="muted">Creates a realm entry with that name (mutable systems only).</span>
          </form>`
        : s.writable === false
          ? html`<p class="lead muted">This system comes from a configured repository; realm settings are read-only.</p>`
          : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-system-realms': SystemRealms;
  }
}
