import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { BffError, getAuditEvent, type AuditEvent, type AuditValueField } from '../../bff.js';
import { systemHref } from '../../router.js';
import { FIRST_ORDER, timeAgo, type FilterForm, type SortBy } from './model.js';

export type AuditNarrowDetail = { field: AuditValueField; value: string };

/**
 * Audit trail table: sortable headers, one row per event, expandable detail with on-demand arguments.
 */
@customElement('kc-mcp-audit-table')
export class AuditTable extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
    }
    .table {
      overflow-x: auto;
    }
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
    .line {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
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
    button.sort {
      padding: 0;
      border: none;
      background: none;
      color: inherit;
      font: inherit;
      font-weight: 600;
      white-space: nowrap;
      cursor: pointer;
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
      cursor: pointer;
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
    .error {
      color: var(--error, #cf222e);
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
    button.link {
      padding: 0;
      border: none;
      background: none;
      color: var(--accent, #1f6feb);
      font: inherit;
      font-weight: 400;
      text-align: left;
      cursor: pointer;
    }
    button.link:hover {
      text-decoration: underline;
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
  `;

  @property({ attribute: false })
  events: AuditEvent[] = [];

  /** Sort state of the applied search (column headers). */
  @property({ attribute: false })
  appliedForm: FilterForm = undefined!;

  /** `kc-mcp.ui.trace-url` template with `{traceId}` / `{spanId}`, or empty. */
  @property()
  traceUrl = '';

  /** The ids of the entries opened on this page. */
  @state()
  private opened = new Set<number>();

  /** Arguments asked for, by event id: loading, the arguments, or why they could not be read. */
  @state()
  private args = new Map<number, 'loading' | { value: unknown } | { error: string }>();

  /** Another page of events: nothing stays open, and arguments read before are dropped. */
  protected willUpdate(changed: Map<string, unknown>): void {
    if (changed.has('events')) {
      this.opened = new Set();
      this.args = new Map();
    }
  }

  private sortBy(sort: SortBy): void {
    const order =
      this.appliedForm.sort === sort ? (this.appliedForm.order === 'asc' ? 'desc' : 'asc') : FIRST_ORDER[sort];
    this.dispatchEvent(
      new CustomEvent<{ sort: SortBy; order: 'asc' | 'desc' }>('sort', {
        detail: { sort, order },
        bubbles: true,
        composed: true,
      }),
    );
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

  private narrow(field: AuditValueField, value: string | null | undefined): void {
    if (value) {
      this.dispatchEvent(
        new CustomEvent<AuditNarrowDetail>('narrow', {
          detail: { field, value },
          bubbles: true,
          composed: true,
        }),
      );
    }
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

  /**
   * The trace id, linked to the tracing or logging system when the server names one (kc-mcp.ui.trace-url, a
   * template with {traceId} and {spanId}); only http(s) links are followed.
   */
  private traceLink(e: AuditEvent) {
    if (!e.traceId) {
      return null;
    }
    const url = this.traceUrl
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

  render() {
    return html`
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
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-audit-table': AuditTable;
  }
  interface HTMLElementEventMap {
    sort: CustomEvent<{ sort: SortBy; order: 'asc' | 'desc' }>;
    narrow: CustomEvent<AuditNarrowDetail>;
  }
}
