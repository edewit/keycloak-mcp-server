import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { BffError, getSystem, type System } from '../bff.js';
import { systemHref, systemsHref, type SystemTab } from '../router.js';
import './system-realms.js';
import './system-settings.js';

/** System detail: header, Settings | Realms tabs, child outlet. */
@customElement('kc-mcp-system-page')
export class SystemPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    a.back {
      color: var(--accent, #1f6feb);
      text-decoration: none;
      font-size: 0.9rem;
    }
    a.back:hover {
      text-decoration: underline;
    }
    h2 {
      font-size: 1.1rem;
      margin: 0.35rem 0 0.25rem;
    }
    .lead {
      margin: 0 0 0.75rem;
      color: var(--muted, #656d76);
      font-size: 0.9rem;
    }
    .lead code {
      font-size: 0.85em;
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
    .tabs {
      display: flex;
      gap: 0.25rem;
      border-bottom: 1px solid var(--border, #d0d7de);
      margin: 0 0 1rem;
    }
    .tabs a {
      color: var(--fg, inherit);
      text-decoration: none;
      padding: 0.5rem 0.85rem;
      border-bottom: 2px solid transparent;
      margin-bottom: -1px;
      font-weight: 500;
      font-size: 0.9rem;
    }
    .tabs a:hover {
      color: var(--accent, #1f6feb);
    }
    .tabs a[aria-current='page'] {
      color: var(--accent, #1f6feb);
      border-bottom-color: var(--accent, #1f6feb);
    }
    .error {
      color: var(--error, #cf222e);
    }
    .muted {
      color: var(--muted, #656d76);
    }
  `;

  @property()
  alias = '';

  @property()
  tab: SystemTab = 'settings';

  @state()
  private system: System | null = null;

  @state()
  private error: string | null = null;

  @state()
  private busy = false;

  connectedCallback(): void {
    super.connectedCallback();
    void this.load();
  }

  protected updated(changed: Map<string, unknown>): void {
    if (changed.has('alias') && changed.get('alias') !== undefined) {
      void this.load();
    }
  }

  private async load(): Promise<void> {
    if (!this.alias) {
      this.system = null;
      return;
    }
    this.busy = true;
    this.error = null;
    try {
      this.system = await getSystem(this.alias);
    } catch (e) {
      this.system = null;
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

  render() {
    if (!this.alias) {
      return html`<p class="error">No system selected.</p>`;
    }
    if (this.busy && !this.system) {
      return html`<p class="muted">Loading…</p>`;
    }
    if (!this.system) {
      return html`
        <a class="back" href=${systemsHref()}>← Systems</a>
        ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      `;
    }
    const s = this.system;
    const title = s.displayName || s.alias;
    const active = this.tab === 'realms' ? 'realms' : 'settings';
    return html`
      <a class="back" href=${systemsHref()}>← Systems</a>
      <h2>${title}</h2>
      <p class="lead">
        Alias <code>${s.alias}</code>
        ${s.source ? html` · source <code>${s.source}</code>` : nothing}
        ${s.writable === false ? html` <span class="badge">read-only source</span>` : nothing}
      </p>
      <nav class="tabs" aria-label="System">
        <a
          href=${systemHref(s.alias, 'settings')}
          aria-current=${active === 'settings' ? 'page' : nothing}
          >Settings</a
        >
        <a
          href=${systemHref(s.alias, 'realms')}
          aria-current=${active === 'realms' ? 'page' : nothing}
          >Realms</a
        >
      </nav>
      ${active === 'realms'
        ? html`<kc-mcp-system-realms .system=${s}></kc-mcp-system-realms>`
        : html`<kc-mcp-system-settings
            embedded
            .alias=${s.alias}
            @system-saved=${() => this.load()}
          ></kc-mcp-system-settings>`}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-system-page': SystemPage;
  }
}
