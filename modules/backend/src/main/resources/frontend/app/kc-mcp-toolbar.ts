import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement } from 'lit/decorators.js';
import { logout } from './bff.js';
import { overviewHref } from './router.js';
import { sessionContext, type SessionState } from './session-context.js';

/** Top masthead: brand + user / sign-out (nav lives in the sidebar). */
@customElement('kc-mcp-toolbar')
export class KcMcpToolbar extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    header {
      display: flex;
      align-items: center;
      gap: 1.25rem;
      padding: 0.75rem 1.5rem;
      border-bottom: 1px solid var(--border, #d0d7de);
      background: var(--card, #fff);
      min-height: 3.25rem;
      box-sizing: border-box;
    }
    h1 {
      font-size: 1.1rem;
      margin: 0;
      flex: 1;
    }
    h1 a {
      color: inherit;
      text-decoration: none;
    }
    h1 a:hover {
      text-decoration: underline;
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      align-items: center;
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      border: 1px solid var(--border, #8b949e);
      background: transparent;
      color: var(--fg, inherit);
      cursor: pointer;
    }
  `;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  render() {
    const s = this.session?.me;
    const signedIn = !!s?.authenticated;
    return html`
      <header>
        <h1><a href=${overviewHref()}>Keycloak MCP</a></h1>
        ${signedIn
          ? html`<div class="row">
              <span>${s!.name ?? s!.username}</span>
              <button type="button" @click=${() => logout(s!)}>Sign out</button>
            </div>`
          : nothing}
      </header>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-toolbar': KcMcpToolbar;
  }
}
