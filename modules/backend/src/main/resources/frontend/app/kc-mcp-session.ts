import { provide } from '@lit/context';
import { LitElement } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { checkSession, me, type SessionCheck } from './bff.js';
import { sessionContext, type SessionState } from './session-context.js';

/**
 * Session host: loads `/bff/me`, renews on visibility, and {@link provide}s
 * {@link sessionContext}. Renders into light DOM so {@code index.html} owns the
 * layout and sibling components update on their own.
 */
@customElement('kc-mcp-session')
export class KcMcpSession extends LitElement {
  @provide({ context: sessionContext })
  @state()
  private sessionState: SessionState = { me: null, lastCheck: null, error: null };

  private checking = false;

  private readonly onVisible = () => {
    if (document.visibilityState === 'visible' && this.sessionState.me?.authenticated && !this.checking) {
      void this.checkSession();
    }
  };

  private readonly onCheckSession = () => {
    void this.checkSession();
  };

  private readonly onSessionLost = () => {
    void this.refresh();
  };

  /** Light DOM so toolbar, nav and outlet stay siblings declared in index.html. */
  protected createRenderRoot(): HTMLElement | DocumentFragment {
    return this;
  }

  connectedCallback(): void {
    const url = new URL(window.location.href);
    const idp = url.searchParams.get('idp') ?? undefined;
    if (url.searchParams.has('state')) {
      url.searchParams.delete('state');
      window.history.replaceState(null, '', url.pathname + url.search + url.hash);
    }
    if (idp) {
      this.sessionState = { ...this.sessionState, suggestedIdp: idp };
    }
    super.connectedCallback();
    this.addEventListener('check-session', this.onCheckSession);
    this.addEventListener('session-lost', this.onSessionLost);
    document.addEventListener('visibilitychange', this.onVisible);
    window.addEventListener('focus', this.onVisible);
    this.syncStateAttr();
    void this.refresh();
  }

  disconnectedCallback(): void {
    this.removeEventListener('check-session', this.onCheckSession);
    this.removeEventListener('session-lost', this.onSessionLost);
    document.removeEventListener('visibilitychange', this.onVisible);
    window.removeEventListener('focus', this.onVisible);
    super.disconnectedCallback();
  }

  protected updated(): void {
    this.syncStateAttr();
  }

  /** `loading` | `ready` | `error` for document CSS (boot vs shell). */
  private syncStateAttr(): void {
    const state = this.sessionState.error ? 'error' : this.sessionState.me ? 'ready' : 'loading';
    if (this.getAttribute('state') !== state) {
      this.setAttribute('state', state);
    }
  }

  private async checkSession(): Promise<void> {
    this.checking = true;
    try {
      const check: SessionCheck | false = await checkSession();
      this.sessionState = {
        ...this.sessionState,
        lastCheck: { at: new Date(), ok: check !== false },
      };
      await this.refresh();
    } catch (e) {
      this.sessionState = {
        ...this.sessionState,
        error: e instanceof Error ? e.message : String(e),
      };
    } finally {
      this.checking = false;
    }
  }

  private async refresh(): Promise<void> {
    try {
      const next = await me(this.sessionState.suggestedIdp);
      const suggestedIdp =
        next.authenticated && next.idp ? next.idp : this.sessionState.suggestedIdp;
      this.sessionState = {
        ...this.sessionState,
        me: next,
        suggestedIdp,
        error: null,
      };
    } catch (e) {
      this.sessionState = {
        ...this.sessionState,
        me: null,
        error: e instanceof Error ? e.message : String(e),
      };
    }
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-session': KcMcpSession;
  }
}
