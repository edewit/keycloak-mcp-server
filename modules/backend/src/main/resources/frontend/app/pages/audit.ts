import { consume } from '@lit/context';
import { LitElement, css, html, nothing } from 'lit';
import { customElement, state } from 'lit/decorators.js';
import {
  auditValues,
  BffError,
  getAuditEvent,
  searchAudit,
  type AuditEvent,
  type AuditFilter,
  type AuditValueField,
} from '../bff.js';
import '../kc-mcp-help.js';
import { systemHref } from '../router.js';
import { sessionContext, type SessionState } from '../session-context.js';

/** Fields of the filter form; times as the `datetime-local` inputs give them (local time, no zone). */
type FilterForm = {
  caller: string;
  system: string;
  realm: string;
  tool: string;
  level: string;
  outcome: string;
  /** Calls without a caller: `only` them, `exclude` them, or (empty) both. */
  anonymous: string;
  /** What the table is ordered by, and in which direction; not a filter, so Clear all keeps it. */
  sort: SortBy;
  order: 'asc' | 'desc';
  /** `any`: no time filter; `ago`: the last `agoValue` `agoUnit`s; `range`: between `from` and `to`. */
  timeMode: TimeMode;
  agoValue: string;
  agoUnit: AgoUnit;
  from: string;
  to: string;
};

/** Units of "in the last ...", in milliseconds. */
const AGO_UNITS = {
  minutes: 60_000,
  hours: 3_600_000,
  days: 86_400_000,
  weeks: 604_800_000,
} as const;

type AgoUnit = keyof typeof AGO_UNITS;

type TimeMode = 'any' | 'ago' | 'range';

type SortBy = 'when' | 'took' | 'caller';

/** The direction a column starts with: newest and slowest first, names from A. */
const FIRST_ORDER: Record<SortBy, 'asc' | 'desc'> = { when: 'desc', took: 'desc', caller: 'asc' };

const CALLERS = [
  { value: '', label: 'All' },
  { value: 'exclude', label: 'Signed in' },
  { value: 'only', label: 'Anonymous' },
] as const;

const LEVELS = [
  { value: '', label: 'All' },
  { value: 'READ', label: 'Read' },
  { value: 'WRITE', label: 'Write' },
  { value: 'DESTRUCTIVE', label: 'Destructive' },
] as const;

const OUTCOMES = [
  { value: '', label: 'All' },
  { value: 'ok', label: 'OK' },
  { value: 'error', label: 'Refused or failed' },
] as const;

const TIME_MODES: { value: TimeMode; label: string }[] = [
  { value: 'any', label: 'Any time' },
  { value: 'ago', label: 'Last …' },
  { value: 'range', label: 'Between …' },
];

const TEXT_FIELDS: { field: AuditValueField; label: string; placeholder: string }[] = [
  { field: 'caller', label: 'Caller', placeholder: 'any caller' },
  { field: 'system', label: 'System', placeholder: 'any system' },
  { field: 'realm', label: 'Realm', placeholder: 'any realm' },
  { field: 'tool', label: 'Tool', placeholder: 'any tool' },
];

const EMPTY: FilterForm = {
  caller: '',
  system: '',
  realm: '',
  tool: '',
  level: '',
  outcome: '',
  anonymous: '',
  sort: 'when',
  order: 'desc',
  timeMode: 'any',
  agoValue: '1',
  agoUnit: 'hours',
  from: '',
  to: '',
};

/** Events per page the viewer can choose; the first is the default. */
const PAGE_SIZES = [25, 50, 100, 250] as const;

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
      color: var(--muted, #656d76);
    }
    form {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      margin-bottom: 1rem;
    }
    .fields {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(12rem, 1fr));
      gap: 0.5rem 0.75rem;
    }
    .groups {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem 1.5rem;
      align-items: end;
    }
    label,
    .group {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
      font-size: 0.8rem;
      color: var(--muted, #656d76);
    }
    .inline {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      align-items: center;
    }
    input,
    select {
      font: inherit;
      font-size: 0.9rem;
      height: 2.1rem;
      box-sizing: border-box;
      padding: 0 0.5rem;
      border: 1px solid var(--border, #d0d7de);
      border-radius: 6px;
      background: var(--card, #fff);
      color: var(--fg, inherit);
      min-width: 0;
    }
    input:focus-visible,
    select:focus-visible,
    button:focus-visible {
      outline: 2px solid var(--accent, #1f6feb);
      outline-offset: 1px;
    }
    input.number {
      width: 5rem;
    }
    /* one choice out of a few, applied at once */
    .seg {
      display: inline-flex;
    }
    .seg button {
      height: 2.1rem;
      padding: 0 0.75rem;
      border-radius: 0;
      border: 1px solid var(--border, #d0d7de);
      background: var(--card, #fff);
      color: var(--fg, inherit);
      font-weight: 400;
      font-size: 0.9rem;
      margin-left: -1px;
    }
    .seg button:first-child {
      border-radius: 6px 0 0 6px;
      margin-left: 0;
    }
    .seg button:last-child {
      border-radius: 0 6px 6px 0;
    }
    .seg button[aria-pressed='true'] {
      background: color-mix(in srgb, var(--accent, #1f6feb) 14%, var(--card, #fff));
      border-color: var(--accent, #1f6feb);
      color: var(--accent, #1f6feb);
      font-weight: 600;
      position: relative;
    }
    /* what is applied, each removable */
    .applied {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      align-items: center;
      min-height: 2.1rem;
    }
    .applied .spacer {
      flex: 1;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      font-size: 0.85rem;
      padding: 0.15rem 0.3rem 0.15rem 0.6rem;
      border-radius: 999px;
      background: color-mix(in srgb, var(--accent, #1f6feb) 12%, transparent);
      color: var(--fg, inherit);
    }
    .chip button {
      padding: 0 0.3rem;
      border: none;
      background: none;
      color: var(--muted, #656d76);
      font-size: 1rem;
      line-height: 1;
      border-radius: 999px;
    }
    .chip button:hover {
      color: var(--error, #cf222e);
    }
    .per-page {
      flex-direction: row;
      align-items: center;
      gap: 0.4rem;
    }
    button {
      font: inherit;
      padding: 0.4rem 0.9rem;
      border-radius: 6px;
      border: 1px solid var(--accent, #1f6feb);
      background: var(--accent, #1f6feb);
      color: #fff;
      cursor: pointer;
      font-weight: 500;
    }
    button.link {
      padding: 0;
      border: none;
      background: none;
      color: var(--accent, #1f6feb);
      font-weight: 400;
      text-align: left;
    }
    button.link:hover {
      text-decoration: underline;
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
    .table {
      overflow-x: auto;
    }
    /* fixed columns: opening an entry or a long message never moves them */
    table {
      width: 100%;
      min-width: 60rem;
      table-layout: fixed;
      border-collapse: collapse;
      font-size: 0.875rem;
    }
    col.toggle {
      width: 2.5rem;
    }
    col.at {
      width: 12.5rem;
    }
    col.caller {
      width: 13%;
    }
    col.tool {
      width: 25%;
    }
    col.target {
      width: 13%;
    }
    col.took {
      width: 5.5rem;
    }
    td {
      overflow-wrap: anywhere;
    }
    /* one line per entry; the entry opened shows the rest */
    .line {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    /* the level always shows; a long tool name is the part that shortens */
    .line.tool {
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }
    .line.tool .badge {
      flex: none;
    }
    .line.tool button {
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    tr.open > td {
      border-bottom-color: transparent;
      background: color-mix(in srgb, var(--accent, #1f6feb) 5%, transparent);
    }
    tr.detail > td {
      padding: 0 0.6rem 0.9rem 3.1rem;
      background: color-mix(in srgb, var(--accent, #1f6feb) 5%, transparent);
    }
    td.took {
      text-align: right;
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
    }
    th.took {
      text-align: right;
    }
    /* a column header that sorts */
    button.sort {
      padding: 0;
      border: none;
      background: none;
      color: inherit;
      font: inherit;
      font-weight: 600;
      white-space: nowrap;
    }
    button.sort span {
      opacity: 0.45;
    }
    button.sort.active {
      color: var(--accent, #1f6feb);
    }
    button.sort.active span {
      opacity: 1;
    }
    button.toggle {
      width: 1.6rem;
      height: 1.6rem;
      padding: 0;
      border: none;
      border-radius: 4px;
      background: none;
      color: var(--muted, #656d76);
      font-size: 0.8rem;
      line-height: 1;
    }
    button.toggle:hover {
      background: color-mix(in srgb, var(--fg, #1f2328) 8%, transparent);
    }
    dl {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 0.25rem 1rem;
      margin: 0;
    }
    dt {
      color: var(--muted, #656d76);
    }
    dd {
      margin: 0;
      min-width: 0;
    }
    th,
    td {
      text-align: left;
      padding: 0.45rem 0.6rem;
      border-bottom: 1px solid var(--border, #d0d7de);
      vertical-align: top;
    }
    th {
      color: var(--muted, #656d76);
      font-weight: 600;
      white-space: nowrap;
    }
    td.when {
      white-space: nowrap;
    }
    code {
      font-size: 0.85em;
    }
    a {
      color: var(--accent, #1f6feb);
      text-decoration: none;
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
      padding: 0.05rem 0.4rem;
      border-radius: 4px;
      border: 1px solid var(--border, #d0d7de);
      color: var(--muted, #656d76);
      white-space: nowrap;
    }
    .badge.write {
      border-color: color-mix(in srgb, var(--accent, #1f6feb) 60%, transparent);
      color: var(--accent, #1f6feb);
    }
    .badge.destructive,
    .badge.failed {
      border-color: color-mix(in srgb, var(--error, #cf222e) 60%, transparent);
      color: var(--error, #cf222e);
    }
    pre {
      margin: 0.35rem 0 0;
      padding: 0.5rem;
      background: color-mix(in srgb, var(--fg, #1f2328) 5%, transparent);
      border-radius: 6px;
      font-size: 0.8rem;
      white-space: pre-wrap;
      word-break: break-word;
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
      margin-right: 0.6rem;
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

  /** Completions per text filter, from the recorded values. */
  @state()
  private completions: Partial<Record<AuditValueField, string[]>> = {};

  private completionTimer?: ReturnType<typeof setTimeout>;

  /** The ids of the entries opened on this page. */
  @state()
  private opened = new Set<number>();

  /** Arguments asked for, by event id: loading, the arguments, or why they could not be read. */
  @state()
  private args = new Map<number, 'loading' | { value: unknown } | { error: string }>();

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

  private filterOf(form: FilterForm): AuditFilter {
    return {
      caller: form.caller,
      system: form.system,
      realm: form.realm,
      tool: form.tool,
      level: form.level,
      outcome: form.outcome,
      anonymous: form.anonymous,
      // the server's default order (newest first) needs no parameters
      sort: form.sort === 'when' && form.order === 'desc' ? undefined : form.sort,
      order: form.sort === 'when' && form.order === 'desc' ? undefined : form.order,
      // "in the last ..." becomes a start when the search runs; the pages of that search keep it
      from:
        form.timeMode === 'ago'
          ? agoInstant(form.agoValue, form.agoUnit)
          : form.timeMode === 'range'
            ? toInstant(form.from)
            : undefined,
      to: form.timeMode === 'range' ? toInstant(form.to) : undefined,
      limit: this.pageSize,
    };
  }

  /** The first page of what the form asks for. */
  private async search(): Promise<void> {
    clearTimeout(this.applyTimer);
    this.applied = this.filterOf(this.form);
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
      // another page: nothing stays open, and arguments read before are dropped
      this.opened = new Set();
      this.args = new Map();
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

  private onSubmit(e: Event): void {
    e.preventDefault();
    this.applyIfChanged();
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

  /** A new page size starts over at the newest events, with the same filters. */
  private setPageSize(e: Event): void {
    this.pageSize = Number((e.target as HTMLSelectElement).value);
    void this.search();
  }

  private clearFilters(): void {
    this.form = { ...EMPTY, sort: this.form.sort, order: this.form.order };
    this.applyIfChanged();
  }

  private setField(field: keyof FilterForm, e: Event): void {
    const value = (e.target as HTMLInputElement | HTMLSelectElement).value;
    this.form = { ...this.form, [field]: value };
  }

  /** Sets fields and applies them: a choice, a removed chip, a click on a value of a row. */
  private choose(change: Partial<FilterForm>): void {
    this.form = { ...this.form, ...change };
    this.applyIfChanged();
  }

  /** A click on a column: that column in its first direction, or the other direction if it is the sort already. */
  private sortBy(sort: SortBy): void {
    const order = this.form.sort === sort ? (this.form.order === 'asc' ? 'desc' : 'asc') : FIRST_ORDER[sort];
    this.choose({ sort, order });
  }

  private sortHeader(sort: SortBy, label: string, cls = '') {
    const active = this.appliedForm.sort === sort;
    const ascending = this.appliedForm.order === 'asc';
    return html`<th class=${cls} aria-sort=${active ? (ascending ? 'ascending' : 'descending') : 'none'}>
      <button class="sort ${active ? 'active' : ''}" title="Sort by ${label.toLowerCase()}" @click=${() => this.sortBy(sort)}>
        ${label}<span aria-hidden="true">${active ? (ascending ? ' ▲' : ' ▼') : ' ↕'}</span>
      </button>
    </th>`;
  }

  /** Narrow to one value of a row (a click on a caller or tool). */
  private narrow(field: AuditValueField, value: string | null | undefined): void {
    if (value) {
      this.choose({ [field]: value });
    }
  }

  /**
   * A text filter, completed from the values recorded in the audit trail (a datalist, asked for on focus and, a
   * moment after the last key, for what was typed). It applies on Enter, on leaving the field and on picking a
   * completion.
   */
  private input(field: AuditValueField, label: string, placeholder: string) {
    const listId = `audit-${field}-values`;
    return html`<label
      >${label}
      <input
        type="search"
        .value=${this.form[field]}
        placeholder=${placeholder}
        autocomplete="off"
        list=${listId}
        @focus=${() => this.complete(field, this.form[field])}
        @input=${(e: Event) => {
          this.setField(field, e);
          const value = this.form[field];
          // a completion picked from the list, or the field emptied with its ×: no Enter needed
          if (value === '' || (this.completions[field] ?? []).includes(value)) {
            this.applyIfChanged();
          } else {
            this.completeSoon(field, value);
          }
        }}
        @change=${() => this.applyIfChanged()}
      /><datalist id=${listId}>
        ${(this.completions[field] ?? []).map((v) => html`<option value=${v}></option>`)}
      </datalist></label
    >`;
  }

  private completeSoon(field: AuditValueField, text: string): void {
    clearTimeout(this.completionTimer);
    this.completionTimer = setTimeout(() => this.complete(field, text), 200);
  }

  private async complete(field: AuditValueField, text: string): Promise<void> {
    try {
      const values = await auditValues(field, text);
      this.completions = { ...this.completions, [field]: values };
    } catch {
      // completions are a convenience: a failure leaves the input as it is
    }
  }

  /** One choice out of a few as a row of buttons; the pressed one is the current value. */
  private segmented<T extends string>(
    label: string,
    options: readonly { value: T; label: string }[],
    current: T,
    pick: (value: T) => void,
  ) {
    return html`<div class="seg" role="group" aria-label=${label}>
      ${options.map(
        (o) =>
          html`<button type="button" aria-pressed=${o.value === current ? 'true' : 'false'} @click=${() => pick(o.value)}>
            ${o.label}
          </button>`,
      )}
    </div>`;
  }

  private renderTime() {
    const mode = this.form.timeMode;
    return html`<div class="group">
      Time
      <div class="inline">
        ${this.segmented('Time', TIME_MODES, mode, (timeMode) => this.choose({ timeMode }))}
        ${mode === 'ago'
          ? html`<input
                class="number"
                type="number"
                min="1"
                step="1"
                aria-label="How many"
                .value=${this.form.agoValue}
                @input=${(e: Event) => {
                  this.setField('agoValue', e);
                  this.applySoon();
                }}
              />
              <select
                aria-label="Unit"
                @change=${(e: Event) => this.choose({ agoUnit: (e.target as HTMLSelectElement).value as AgoUnit })}
              >
                ${(Object.keys(AGO_UNITS) as AgoUnit[]).map(
                  (u) => html`<option value=${u} ?selected=${this.form.agoUnit === u}>${u}</option>`,
                )}
              </select>`
          : mode === 'range'
            ? html`<input
                  type="datetime-local"
                  aria-label="From"
                  .value=${this.form.from}
                  @change=${(e: Event) => this.choose({ from: (e.target as HTMLInputElement).value })}
                />
                <span>until</span>
                <input
                  type="datetime-local"
                  aria-label="Until"
                  .value=${this.form.to}
                  @change=${(e: Event) => this.choose({ to: (e.target as HTMLInputElement).value })}
                />`
            : nothing}
      </div>
    </div>`;
  }

  /** The filters the rows shown were searched with, each with a button that removes it. */
  private chips(): { label: string; without: Partial<FilterForm> }[] {
    const f = this.appliedForm;
    const chips: { label: string; without: Partial<FilterForm> }[] = [];
    for (const { field, label } of TEXT_FIELDS) {
      if (f[field]) {
        chips.push({ label: `${label}: ${f[field]}`, without: { [field]: '' } });
      }
    }
    if (f.anonymous) {
      chips.push({
        label: f.anonymous === 'only' ? 'Callers: anonymous only' : 'Callers: signed in only',
        without: { anonymous: '' },
      });
    }
    if (f.level) {
      chips.push({ label: `Level: ${f.level.toLowerCase()}`, without: { level: '' } });
    }
    if (f.outcome) {
      chips.push({ label: f.outcome === 'ok' ? 'Outcome: ok' : 'Outcome: refused or failed', without: { outcome: '' } });
    }
    if (f.timeMode === 'ago' && agoInstant(f.agoValue, f.agoUnit)) {
      const unit = Number(f.agoValue) === 1 ? f.agoUnit.slice(0, -1) : f.agoUnit;
      chips.push({ label: `Last ${f.agoValue} ${unit}`, without: { timeMode: 'any' } });
    }
    if (f.timeMode === 'range' && (f.from || f.to)) {
      const from = f.from ? `from ${new Date(f.from).toLocaleString()}` : '';
      const to = f.to ? `until ${new Date(f.to).toLocaleString()}` : '';
      chips.push({ label: [from, to].filter(Boolean).join(' '), without: { timeMode: 'any' } });
    }
    return chips;
  }

  private renderFilters() {
    const chips = this.chips();
    return html`
      <form @submit=${this.onSubmit}>
        <div class="fields">${TEXT_FIELDS.map((t) => this.input(t.field, t.label, t.placeholder))}</div>
        <div class="groups">
          <div class="group">
            Callers
            ${this.segmented('Callers', CALLERS, this.form.anonymous, (anonymous) => this.choose({ anonymous }))}
          </div>
          <div class="group">
            Level ${this.segmented('Level', LEVELS, this.form.level, (level) => this.choose({ level }))}
          </div>
          <div class="group">
            Outcome
            ${this.segmented('Outcome', OUTCOMES, this.form.outcome, (outcome) => this.choose({ outcome }))}
          </div>
          ${this.renderTime()}
        </div>
        <div class="applied">
          ${chips.length === 0
            ? html`<span class="muted">No filter: all events.</span>`
            : html`${chips.map(
                  (c) =>
                    html`<span class="chip"
                      >${c.label}<button
                        type="button"
                        aria-label="Remove filter ${c.label}"
                        title="Remove this filter"
                        @click=${() => this.choose(c.without)}
                      >
                        ×
                      </button></span
                    >`,
                )}
                <button type="button" class="link" @click=${this.clearFilters}>Clear all</button>
                ${this.appliedForm.caller
                  ? html`<span class="muted">· the link to this view leaves the caller out</span>`
                  : nothing}`}
          <span class="spacer"></span>
          <button
            type="button"
            class="secondary"
            title=${this.appliedForm.caller
              ? 'Copy a link to this view. The caller filter is not part of the link: names stay out of URLs.'
              : 'Copy a link to this view with its filters'}
            @click=${this.copyLink}
          >
            ${this.copied ? 'Copied' : 'Copy link'}
          </button>
          <button
            type="button"
            class="secondary"
            title="Load the newest events again"
            ?disabled=${this.busy}
            @click=${() => this.search()}
          >
            Refresh
          </button>
        </div>
      </form>
    `;
  }

  private toggle(id: number): void {
    const opened = new Set(this.opened);
    if (!opened.delete(id)) {
      opened.add(id);
    }
    this.opened = opened;
  }

  /**
   * Arguments are fetched for one event, when asked for: they may hold personal data, so they are neither sent with
   * the list nor shown by opening an entry.
   */
  private async showArguments(id: number): Promise<void> {
    this.args = new Map(this.args).set(id, 'loading');
    try {
      const event = await getAuditEvent(id);
      this.args = new Map(this.args).set(id, { value: event.args ?? {} });
    } catch (e) {
      const error = e instanceof BffError ? `${e.status} ${e.code}: ${e.message}` : String(e);
      this.args = new Map(this.args).set(id, { error });
      if (e instanceof BffError && e.sessionLost) {
        this.dispatchEvent(new CustomEvent('session-lost', { bubbles: true, composed: true }));
      }
    }
  }

  private hideArguments(id: number): void {
    const args = new Map(this.args);
    args.delete(id);
    this.args = args;
  }

  private renderEvent(e: AuditEvent) {
    const failed = e.outcome !== 'ok';
    const caller = e.caller?.name || e.caller?.subject;
    const open = this.opened.has(e.id);
    return html`
      <tr class=${open ? 'open' : ''}>
        <td>
          <button
            class="toggle"
            aria-expanded=${open ? 'true' : 'false'}
            aria-label=${open ? 'Hide details' : 'Show details'}
            title=${open ? 'Hide details' : 'Show details'}
            @click=${() => this.toggle(e.id)}
          >
            ${open ? '▼' : '▶'}
          </button>
        </td>
        <td class="when" title=${e.at}>${new Date(e.at).toLocaleString()}</td>
        <td>
          <div class="line">
            ${e.caller?.name
              ? html`<button class="link" title="only this caller" @click=${() => this.narrow('caller', e.caller?.name)}>
                  ${e.caller.name}
                </button>`
              : caller
                ? html`<span title=${caller}>${caller}</span>`
                : html`<span class="muted">anonymous</span>`}
            ${e.caller?.delegated
              ? html` <span class="badge" title="called with the caller's token">delegated</span>`
              : nothing}
          </div>
        </td>
        <td>
          <div class="line tool">
            <span class="badge ${e.level.toLowerCase()}">${e.level.toLowerCase()}</span>
            <button class="link" title="only this tool: ${e.tool}" @click=${() => this.narrow('tool', e.tool)}>
              <code>${e.tool}</code>
            </button>
          </div>
        </td>
        <td>
          <div class="line">
            ${e.system
              ? html`<a href=${systemHref(e.system)}>${e.system}</a>${e.realm
                    ? html`<span class="muted"> / ${e.realm}</span>`
                    : nothing}`
              : html`<span class="muted">–</span>`}
          </div>
        </td>
        <td>
          <div class="line" title=${e.message ?? ''}>
            <span class="badge ${failed ? 'failed' : ''}">${e.outcome}</span>
            ${e.message ? html`<span class="muted">${e.message}</span>` : nothing}
          </div>
        </td>
        <td class="took">${e.durationMs} ms</td>
      </tr>
      ${open ? this.renderDetail(e) : nothing}
    `;
  }

  /**
   * The trace id, linked to the tracing or logging system when the server names one (kc-mcp.ui.trace-url, a
   * template with {traceId} and {spanId}); only http(s) links are followed.
   */
  private traceLink(e: AuditEvent) {
    if (!e.traceId) {
      return null;
    }
    const template = this.session?.me?.traceUrl ?? '';
    const url = template
      .replaceAll('{traceId}', encodeURIComponent(e.traceId))
      .replaceAll('{spanId}', encodeURIComponent(e.spanId ?? ''));
    return /^https?:\/\//i.test(url)
      ? html`<a href=${url} target="_blank" rel="noopener noreferrer" title="Open the trace"><code>${e.traceId}</code></a>`
      : html`<code>${e.traceId}</code>`;
  }

  private renderDetail(e: AuditEvent) {
    const args = this.args.get(e.id);
    const row = (label: string, value: unknown) =>
      value === null || value === undefined || value === '' ? nothing : html`<dt>${label}</dt><dd>${value}</dd>`;
    return html`
      <tr class="detail">
        <td colspan="7">
          <dl>
            ${row('Message', e.message)}
            ${row('Time', html`${e.at} <span class="muted">(${timeAgo(e.at)})</span>`)}
            ${row('Caller', e.caller?.name)}
            ${row('Subject', e.caller?.subject)} ${row('Caller realm', e.caller?.realm)} ${row('Client', e.client)}
            ${row('Called', e.via === 'execute_tool' ? 'through execute_tool' : e.via)}
            ${row('Connection', e.connectionId)} ${row('Event', e.id)} ${row('Trace', this.traceLink(e))}
            ${row('Span', e.spanId ? html`<code>${e.spanId}</code>` : null)}
            <dt>Arguments</dt>
            <dd>
              ${!e.hasArgs
                ? html`<span class="muted">none recorded</span>`
                : args === undefined
                  ? html`<button class="link" @click=${() => this.showArguments(e.id)}>Show arguments</button>
                      <span class="muted">· may contain personal data</span>`
                  : args === 'loading'
                    ? html`<span class="muted">loading …</span>`
                    : 'error' in args
                      ? html`<span class="error">${args.error}</span>`
                      : html`<button class="link" @click=${() => this.hideArguments(e.id)}>Hide arguments</button>
                          <pre>${typeof args.value === 'string' ? args.value : JSON.stringify(args.value, null, 2)}</pre>`}
            </dd>
          </dl>
        </td>
      </tr>
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
      ${this.renderFilters()} ${this.error ? html`<p class="error">${this.error}</p>` : nothing}
      ${this.events.length > 0 ? this.renderPager(false) : nothing}
      ${this.events.length === 0 && !this.busy && !this.error
        ? html`<p>No events match.</p>`
        : html`
            <div class="table">
              <table>
                <colgroup>
                  <col class="toggle" />
                  <col class="at" />
                  <col class="caller" />
                  <col class="tool" />
                  <col class="target" />
                  <col />
                  <col class="took" />
                </colgroup>
                <thead>
                  <tr>
                    <th><span aria-hidden="true"></span></th>
                    ${this.sortHeader('when', 'When')} ${this.sortHeader('caller', 'Caller')}
                    <th>Tool</th>
                    <th>System / realm</th>
                    <th>Outcome</th>
                    ${this.sortHeader('took', 'Took', 'took')}
                  </tr>
                </thead>
                <tbody>
                  ${this.events.map((e) => this.renderEvent(e))}
                </tbody>
              </table>
            </div>
          `}
      ${this.events.length > 0 ? this.renderPager(true) : nothing}
    `;
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
}

/** How long ago a moment was, next to the exact instant ("4 minutes ago"). */
function timeAgo(instant: string): string {
  const date = new Date(instant);
  if (Number.isNaN(date.getTime())) {
    return '';
  }
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ['year', 31_536_000],
    ['month', 2_592_000],
    ['week', 604_800],
    ['day', 86_400],
    ['hour', 3_600],
    ['minute', 60],
  ];
  const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  const step = steps.find(([, size]) => Math.abs(seconds) >= size);
  return step ? relative.format(Math.round(seconds / step[1]), step[0]) : relative.format(seconds, 'second');
}

/** Units of "last ..." as the letter the query string uses (`last=2w`). */
const UNIT_LETTERS: Record<AgoUnit, string> = { minutes: 'm', hours: 'h', days: 'd', weeks: 'w' };

/**
 * The filters as query parameters: `system`, `realm`, `tool`, `level`, `outcome`, `last` (`90m`, `2w`) or `from` /
 * `to` (ISO-8601 instants, so a link means the same moment in every time zone) and `size`. Defaults are left out;
 * the caller always is.
 */
function toQuery(form: FilterForm, pageSize: number): URLSearchParams {
  const q = new URLSearchParams();
  for (const field of ['system', 'realm', 'tool', 'level', 'outcome', 'anonymous'] as const) {
    if (form[field]) {
      q.set(field, form[field]);
    }
  }
  if (form.sort !== EMPTY.sort || form.order !== EMPTY.order) {
    q.set('sort', form.sort);
    q.set('order', form.order);
  }
  if (form.timeMode === 'ago' && agoInstant(form.agoValue, form.agoUnit)) {
    q.set('last', `${Number(form.agoValue)}${UNIT_LETTERS[form.agoUnit]}`);
  }
  if (form.timeMode === 'range') {
    const from = toInstant(form.from);
    const to = toInstant(form.to);
    if (from) {
      q.set('from', from);
    }
    if (to) {
      q.set('to', to);
    }
  }
  if (pageSize !== PAGE_SIZES[0]) {
    q.set('size', String(pageSize));
  }
  return q;
}

/** The reverse of {@link toQuery}; anything it does not understand is ignored. */
function fromQuery(q: URLSearchParams): { form: FilterForm; pageSize: number } {
  const form: FilterForm = { ...EMPTY };
  for (const field of ['system', 'realm', 'tool'] as const) {
    form[field] = q.get(field)?.trim() ?? '';
  }
  const level = (q.get('level') ?? '').toUpperCase();
  if (LEVELS.some((l) => l.value === level)) {
    form.level = level;
  }
  const anonymous = q.get('anonymous') ?? '';
  if (CALLERS.some((c) => c.value === anonymous)) {
    form.anonymous = anonymous;
  }
  const sort = q.get('sort') ?? '';
  if (sort === 'when' || sort === 'took' || sort === 'caller') {
    form.sort = sort;
    form.order = q.get('order') === 'asc' ? 'asc' : q.get('order') === 'desc' ? 'desc' : FIRST_ORDER[sort];
  }
  const outcome = q.get('outcome') ?? '';
  if (OUTCOMES.some((o) => o.value === outcome)) {
    form.outcome = outcome;
  }
  const last = /^([1-9]\d{0,5})([mhdw])$/.exec(q.get('last') ?? '');
  const from = toLocal(q.get('from'));
  const to = toLocal(q.get('to'));
  if (last) {
    form.timeMode = 'ago';
    form.agoValue = last[1];
    form.agoUnit = (Object.keys(UNIT_LETTERS) as AgoUnit[]).find((u) => UNIT_LETTERS[u] === last[2]) ?? 'hours';
  } else if (from || to) {
    form.timeMode = 'range';
    form.from = from;
    form.to = to;
  }
  const size = Number(q.get('size'));
  const pageSize = (PAGE_SIZES as readonly number[]).includes(size) ? size : PAGE_SIZES[0];
  return { form, pageSize };
}

/** An ISO-8601 instant as the local `datetime-local` value (minutes); empty when it is none. */
function toLocal(instant: string | null): string {
  if (!instant) {
    return '';
  }
  const date = new Date(instant);
  if (Number.isNaN(date.getTime())) {
    return '';
  }
  const two = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())}T${two(date.getHours())}:${two(date.getMinutes())}`;
}

/** "In the last `value` `unit`s" as the instant it starts; empty or not a positive number stays unset. */
function agoInstant(value: string, unit: AgoUnit): string | undefined {
  const n = Number(value);
  if (!value || !Number.isFinite(n) || n <= 0) {
    return undefined;
  }
  return new Date(Date.now() - n * AGO_UNITS[unit]).toISOString();
}

/** A `datetime-local` value (local time) as an ISO-8601 instant; empty stays unset. */
function toInstant(local: string): string | undefined {
  if (!local) {
    return undefined;
  }
  const date = new Date(local);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-audit-page': AuditPage;
  }
}
