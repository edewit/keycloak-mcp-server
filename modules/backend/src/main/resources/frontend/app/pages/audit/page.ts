import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import { BffError, searchAudit, type AuditEvent, type AuditFilter } from '../../bff.js';
import '../../kc-mcp-help.js';
import { sessionContext, type SessionState } from '../../session-context.js';
import './filter.js';
import type { AuditFilterChangeDetail } from './filter.js';
import {
  EMPTY,
  PAGE_SIZES,
  filterOf,
  fromQuery,
  toQuery,
  type FilterForm,
  type SortBy,
} from './model.js';
import './table.js';
import type { AuditNarrowDetail } from './table.js';

/**
 * The audit trail (GET /bff/api/audit): one row per tool call, newest first, filtered and paged on the server. A
 * filter applies as it is chosen (no search button); the chips under the filters name what is applied and remove
 * it one by one. Read only; operators and viewers alike.
 */
@customElement('kc-mcp-audit-page')
export class AuditPage extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    h2 {
      font-size: 1rem;
      margin: 0 0 0.75rem;
    }
    p {
      margin: 0 0 0.75rem;
      color: var(--muted, #6a6e73);
    }
    .error {
      color: var(--error, #c9190b);
    }
    .muted {
      color: var(--muted, #6a6e73);
    }
    .pager {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
      margin: 0 0 0.75rem;
    }
    .pager.bottom {
      margin: 0.75rem 0 0;
    }
    .pager .buttons {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.4rem;
    }
    .pager .per-page {
      display: flex;
      flex-direction: row;
      align-items: center;
      gap: 0.4rem;
      margin-right: 0.6rem;
      font-size: 0.8rem;
      color: var(--muted, #6a6e73);
    }
    select {
      font: inherit;
      font-size: 0.9rem;
      height: 2.1rem;
      box-sizing: border-box;
      padding: 0 0.5rem;
      border: 1px solid var(--border, #d2d2d2);
      border-radius: var(--radius, 6px);
      background: var(--card, #fff);
      color: var(--fg, inherit);
      min-width: 0;
    }
    select:focus-visible,
    button:focus-visible {
      outline: 2px solid var(--accent, #0066cc);
      outline-offset: 1px;
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: var(--kc-mcp-c-button--BorderRadius, var(--button-radius, 999px));
      border: 1px solid var(--accent, #0066cc);
      background: var(--accent, #0066cc);
      color: #fff;
      cursor: pointer;
      font-weight: 500;
    }
    button.secondary {
      background: transparent;
      color: var(--fg, inherit);
      border-color: var(--border, #6a6e73);
    }
    button:disabled {
      opacity: 0.5;
      cursor: default;
    }
  `;

  @consume({ context: sessionContext, subscribe: true })
  private session?: SessionState;

  @state()
  private form: FilterForm = { ...EMPTY };

  @state()
  private events: AuditEvent[] = [];

  @state()
  private next: string | null = null;

  @state()
  private error: string | null = null;

  @state()
  private busy = false;

  /** The filter of the rows shown, so the other pages continue the same query. */
  private applied: AuditFilter = {};

  /** The form the rows shown were searched with: what the chips name, and what a change is compared to. */
  @state()
  private appliedForm: FilterForm = { ...EMPTY };

  private applyTimer?: ReturnType<typeof setTimeout>;

  @state()
  private copied = false;

  /** The cursor of every page reached so far; the first page has none. */
  private cursors: (string | undefined)[] = [undefined];

  @state()
  private pageIndex = 0;

  @state()
  private total = 0;

  /** Events per page; not a filter, so Clear keeps it. */
  @state()
  private pageSize: number = PAGE_SIZES[0];

  connectedCallback(): void {
    super.connectedCallback();
    // a shared link: the filters of its query string
    const shared = fromQuery(new URLSearchParams(location.search));
    this.form = shared.form;
    this.pageSize = shared.pageSize;
    void this.search();
  }

  /**
   * Keeps the applied filters in the address bar, so the link can be bookmarked or shared; the same entry of the
   * history, not a new one per filter. The caller is left out: a person's name does not belong in a URL (browser
   * history, proxy logs, a chat the link is pasted into).
   */
  private writeUrl(): void {
    const query = toQuery(this.appliedForm, this.pageSize).toString();
    const url = location.pathname + (query ? `?${query}` : '');
    if (url !== location.pathname + location.search) {
      history.replaceState(history.state, '', url);
    }
  }

  private async copyLink(): Promise<void> {
    try {
      await navigator.clipboard.writeText(location.href);
      this.copied = true;
      setTimeout(() => (this.copied = false), 2000);
    } catch {
      // no clipboard access: the address bar has the same link
    }
  }

  /** The first page of what the form asks for. */
  private async search(): Promise<void> {
    clearTimeout(this.applyTimer);
    this.applied = filterOf(this.form, this.pageSize);
    this.appliedForm = { ...this.form };
    this.writeUrl();
    this.cursors = [undefined];
    await this.showPage(0);
  }

  /**
   * Page `index` (0 is the newest) of the applied filter. The API pages by cursor, not by number: the cursor of a
   * page is the `next` of the one before, so only the pages up to one past the furthest seen can be reached.
   */
  private async showPage(index: number): Promise<void> {
    this.busy = true;
    this.error = null;
    try {
      const page = await searchAudit({ ...this.applied, cursor: this.cursors[index] });
      this.events = page.events;
      this.next = page.next;
      this.total = page.total;
      this.pageIndex = index;
      this.cursors = [...this.cursors.slice(0, index + 1), ...(page.next ? [page.next] : [])];
    } catch (e) {
      this.events = [];
      this.next = null;
      this.total = 0;
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

  /** From the pager under the table: back to the top of the page as well. */
  private async turnTo(index: number, fromBottom: boolean): Promise<void> {
    await this.showPage(index);
    if (fromBottom) {
      this.scrollIntoView({ block: 'start' });
    }
  }

  /** Searches when the form differs from what is shown: filters apply as they are chosen, without a button. */
  private applyIfChanged(): void {
    if (JSON.stringify(this.form) !== JSON.stringify(this.appliedForm)) {
      void this.search();
    }
  }

  /** For values that are typed (the number of "last ..."): a moment after the last key. */
  private applySoon(): void {
    clearTimeout(this.applyTimer);
    this.applyTimer = setTimeout(() => this.applyIfChanged(), 400);
  }

  private onFilterChange(e: CustomEvent<AuditFilterChangeDetail>): void {
    this.form = e.detail.form;
    if (e.detail.when === 'draft') {
      return;
    }
    if (e.detail.when === 'soon') {
      this.applySoon();
      return;
    }
    this.applyIfChanged();
  }

  private onSort(e: CustomEvent<{ sort: SortBy; order: 'asc' | 'desc' }>): void {
    this.form = { ...this.form, ...e.detail };
    this.applyIfChanged();
  }

  private onNarrow(e: CustomEvent<AuditNarrowDetail>): void {
    this.form = { ...this.form, [e.detail.field]: e.detail.value };
    this.applyIfChanged();
  }

  /** A new page size starts over at the newest events, with the same filters. */
  private setPageSize(e: Event): void {
    this.pageSize = Number((e.target as HTMLSelectElement).value);
    void this.search();
  }

  private renderPager(bottom: boolean) {
    const first = this.pageIndex * this.pageSize + 1;
    const last = first + this.events.length - 1;
    const pages = Math.max(1, Math.ceil(this.total / this.pageSize));
    const newer = this.pageIndex > 0;
    return html`
      <nav class="pager ${bottom ? 'bottom' : ''}" aria-label="Audit pages">
        <span class="muted">${first}–${last} of ${this.total} · page ${this.pageIndex + 1} of ${pages}</span>
        <span class="buttons">
          <label class="per-page"
            >Per page
            <select @change=${this.setPageSize}>
              ${PAGE_SIZES.map((n) => html`<option value=${n} ?selected=${n === this.pageSize}>${n}</option>`)}
            </select></label
          >
          <button class="secondary" ?disabled=${this.busy || !newer} @click=${() => this.turnTo(0, bottom)}>
            « First
          </button>
          <button
            class="secondary"
            ?disabled=${this.busy || !newer}
            @click=${() => this.turnTo(this.pageIndex - 1, bottom)}
          >
            ‹ Previous
          </button>
          <button
            class="secondary"
            ?disabled=${this.busy || !this.next}
            @click=${() => this.turnTo(this.pageIndex + 1, bottom)}
          >
            Next ›
          </button>
        </span>
      </nav>
    `;
  }

  render() {
    return html`
      <h2>
        Audit
        <kc-mcp-help label="About the audit trail">
          Every tool call the server answered, refusals included, newest first unless a column is sorted. Open an
          entry for its details; its arguments are read only when asked for, as they were recorded: secrets replaced
          by <code>***</code>, personal data as the audit scrubber left it.
        </kc-mcp-help>
      </h2>
      <kc-mcp-audit-filter
        .form=${this.form}
        .appliedForm=${this.appliedForm}
        .busy=${this.busy}
        .copied=${this.copied}
        @filter-change=${this.onFilterChange}
        @copy-link=${this.copyLink}
        @refresh=${() => this.search()}
      ></kc-mcp-audit-filter>
      ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${this.events.length > 0 ? this.renderPager(false) : nothing}
      ${this.events.length === 0 && !this.busy && !this.error
        ? html`<p>No events match.</p>`
        : html`<kc-mcp-audit-table
            .events=${this.events}
            .appliedForm=${this.appliedForm}
            .traceUrl=${this.session?.me?.traceUrl ?? ''}
            @sort=${this.onSort}
            @narrow=${this.onNarrow}
          ></kc-mcp-audit-table>`}
      ${this.events.length > 0 ? this.renderPager(true) : nothing}
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-audit-page': AuditPage;
  }
}
