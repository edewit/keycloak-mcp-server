import { LitElement, css, html, nothing } from 'lit';
import { customElement, property } from 'lit/decorators.js';
import type { System } from '../bff.js';
import { systemHref } from '../router.js';

/** Read-only view of managed realms and MCP entries for one system. */
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
  `;

  @property({ attribute: false })
  system: System | null = null;

  /** System-wide MCP entry is always the first `entries` value from the admin representation. */
  private systemRoot(s: System): string {
    return s.entries?.[0] ?? `/mcp/systems/${s.alias}`;
  }

  private realmEntry(s: System, realm: string): string {
    const root = this.systemRoot(s);
    return (s.entries ?? []).find((e) => e === `${root}/${realm}`) ?? `${root}/${realm}`;
  }

  render() {
    const s = this.system;
    if (!s) {
      return html`<p class="muted">No system loaded.</p>`;
    }
    const root = this.systemRoot(s);
    const allowed = s.allowedRealms ?? [];
    const rows =
      allowed.length === 0
        ? [
            {
              realm: 'All realms',
              note: 'No allowlist — every realm on this Keycloak is in scope for tools (subject to other policy).',
              entry: root,
              isDefault: false,
              all: true,
            },
          ]
        : allowed.map((realm) => ({
            realm,
            note: '',
            entry: this.realmEntry(s, realm),
            isDefault: s.defaultRealm === realm,
            all: false,
          }));

    return html`
      <p class="lead">
        Managed realms for this Keycloak cluster. Edit the default realm and allowlist under
        <a href=${systemHref(s.alias, 'settings')}>Settings</a>.
      </p>
      ${allowed.length > 0
        ? html`<p class="lead muted">System entry (any allowed realm): <code>${root}</code></p>`
        : nothing}
      <table>
        <thead>
          <tr>
            <th>Realm</th>
            <th>MCP entry</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(
            (row) => html`
              <tr>
                <td>
                  ${row.realm}
                  ${row.isDefault ? html`<span class="badge">default</span>` : nothing}
                  ${row.all ? html`<span class="badge">unrestricted</span>` : nothing}
                  ${row.note ? html`<div class="muted">${row.note}</div>` : nothing}
                </td>
                <td><code>${row.entry}</code></td>
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
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-system-realms': SystemRealms;
  }
}
