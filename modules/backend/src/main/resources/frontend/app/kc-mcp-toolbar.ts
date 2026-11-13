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
      color: var(--kc-mcp-c-masthead--Color, var(--masthead-fg, #fff));
    }
    header {
      display: flex;
      align-items: center;
      gap: 1.25rem;
      padding: 0 var(--kc-mcp-c-masthead--PaddingX, 1.5rem);
      border-bottom: 1px solid var(--kc-mcp-c-masthead--BorderColor, var(--masthead-border, #444548));
      background: var(--kc-mcp-c-masthead--BackgroundColor, var(--masthead-bg, #151515));
      min-height: var(--kc-mcp-c-masthead--Height, 4rem);
      box-sizing: border-box;
    }
    h1 {
      font-family: var(--font-heading, 'Red Hat Display', sans-serif);
      font-size: 1.125rem;
      font-weight: var(--kc-mcp-global--FontWeight--normal, 400);
      margin: 0;
      flex: 1;
      letter-spacing: 0.01em;
    }
    h1 a {
      color: inherit;
      text-decoration: none;
    }
    h1 a:hover {
      color: var(--accent, #1fa7f8);
    }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
      color: var(--kc-mcp-c-masthead--Color--muted, var(--masthead-muted, #c7c7c7));
      font-size: var(--kc-mcp-global--FontSize--sm, 0.875rem);
    }
    button {
      font: inherit;
      padding: 0.35rem 1rem;
      border-radius: var(--button-radius, 999px);
      border: 1px solid var(--kc-mcp-c-masthead--BorderColor, var(--masthead-border, #444548));
      background: transparent;
      color: var(--kc-mcp-c-masthead--Color, var(--masthead-fg, #fff));
      cursor: pointer;
    }
    button:hover {
      border-color: var(--kc-mcp-c-masthead--Color--muted, var(--masthead-muted, #c7c7c7));
      background: color-mix(in srgb, #fff 8%, transparent);
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
