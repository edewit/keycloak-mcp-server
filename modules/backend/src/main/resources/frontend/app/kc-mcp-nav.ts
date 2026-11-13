import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { hasCapability } from './bff.js';
import { DEFAULT_PATH, navPath, routes } from './router.js';
import { sessionContext, type SessionState } from './session-context.js';

/**
 * Vertical page nav under the masthead (Keycloak Admin Console–style sidebar).
 */
@customElement('kc-mcp-nav')
export class KcMcpNav extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--kc-mcp-c-nav--Color, var(--fg, inherit));
      background: var(--kc-mcp-c-nav--BackgroundColor, var(--card, #fff));
      border-right: 1px solid var(--kc-mcp-c-nav--BorderColor, var(--border, #d2d2d2));
      box-shadow: var(--kc-mcp-c-nav--BoxShadow, var(--shadow, none));
      min-height: 100%;
      box-sizing: border-box;
    }
    @media (max-width: 640px) {
      :host {
        border-right: none;
        border-bottom: 1px solid var(--kc-mcp-c-nav--BorderColor, var(--border, #d2d2d2));
        box-shadow: none;
      }
      nav {
        flex-direction: row;
        flex-wrap: wrap;
        padding: 0.5rem 0.75rem;
      }
      a {
        border-left: none;
        border-bottom: 3px solid transparent;
        padding: 0.45rem 0.75rem;
      }
      a[aria-current='page'] {
        border-left-color: transparent;
        border-bottom-color: var(--kc-mcp-c-nav--m-current--BorderColor, var(--accent, #0066cc));
      }
    }
    nav {
      display: flex;
      flex-direction: column;
      padding: 1rem 0;
      gap: 0.125rem;
    }
    a {
      display: block;
      color: inherit;
      text-decoration: none;
      padding: 0.65rem 1.5rem;
      border-left: 4px solid transparent;
      font-weight: var(--kc-mcp-global--FontWeight--normal, 400);
    }
    a:hover {
      background: var(--kc-mcp-c-nav--m-hover--BackgroundColor, color-mix(in srgb, var(--fg, #151515) 5%, transparent));
      color: var(--kc-mcp-c-nav--m-hover--Color, var(--accent, #0066cc));
    }
    a[aria-current='page'] {
      font-weight: var(--kc-mcp-global--FontWeight--bold, 700);
      color: var(--kc-mcp-c-nav--m-current--Color, var(--accent, #0066cc));
      border-left-color: var(--kc-mcp-c-nav--m-current--BorderColor, var(--accent, #0066cc));
      background: var(--kc-mcp-c-nav--m-current--BackgroundColor, color-mix(in srgb, var(--accent, #0066cc) 10%, transparent));
    }
  `;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private path = DEFAULT_PATH;

  private readonly onNav = () => {
    this.path = location.pathname;
  };

  connectedCallback(): void {
    super.connectedCallback();
    this.path = location.pathname;
    window.addEventListener('popstate', this.onNav);
    window.addEventListener('kc-mcp-navigate', this.onNav);
  }

  disconnectedCallback(): void {
    window.removeEventListener('popstate', this.onNav);
    window.removeEventListener('kc-mcp-navigate', this.onNav);
    super.disconnectedCallback();
  }

  render() {
    if (!this.session?.me?.authenticated) {
      return nothing;
    }
    const current = navPath(this.path);
    const visible = routes.filter(
      (route) => !route.capability || hasCapability(this.session?.me, route.capability),
    );
    return html`
      <nav aria-label="Management">
        ${visible.map(
          (route) => html`
            <a href=${route.path} aria-current=${current === route.path ? 'page' : nothing}
              >${route.label}</a
            >
          `,
        )}
      </nav>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-nav': KcMcpNav;
  }
  interface WindowEventMap {
    'kc-mcp-navigate': Event;
    'kc-mcp-goto': CustomEvent<{ path: string }>;
  }
}
