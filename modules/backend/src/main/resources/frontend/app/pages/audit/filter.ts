import { LitElement, css, html, nothing } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';
import { auditValues, type AuditValueField } from '../../bff.js';
import {
  AGO_UNITS,
  CALLERS,
  LEVELS,
  OUTCOMES,
  TEXT_FIELDS,
  TIME_MODES,
  chipsOf,
  type AgoUnit,
  type FilterForm,
  type TimeMode,
} from './model.js';

export type AuditFilterChangeDetail = {
  form: FilterForm;
  /**
   * `now`: search when the form differs from what is shown;
   * `soon`: debounce (typed number of "last …");
   * `draft`: keep the form only (typed text waiting for Enter / blur / a completion).
   */
  when: 'now' | 'soon' | 'draft';
};

/**
 * Audit trail filters: text fields with completions, segmented choices, time mode, applied chips,
 * copy-link and refresh. The parent owns the form and applies searches.
 */
@customElement('kc-mcp-audit-filter')
export class AuditFilter extends LitElement {
  static styles = css`
    :host {
      display: block;
      color: var(--fg, inherit);
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
      color: var(--muted, #6a6e73);
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
      border: 1px solid var(--border, #d2d2d2);
      border-radius: var(--radius, 6px);
      background: var(--card, #fff);
      color: var(--fg, inherit);
      min-width: 0;
    }
    input:focus-visible,
    select:focus-visible,
    button:focus-visible {
      outline: 2px solid var(--accent, #0066cc);
      outline-offset: 1px;
    }
    input.number {
      width: 5rem;
    }
    .seg {
      display: inline-flex;
    }
    .seg button {
      height: 2.1rem;
      padding: 0 0.75rem;
      border-radius: 0;
      border: 1px solid var(--border, #d2d2d2);
      background: var(--card, #fff);
      color: var(--fg, inherit);
      font-weight: 400;
      font-size: 0.9rem;
      margin-left: -1px;
    }
    .seg button:first-child {
      border-radius: var(--radius, 6px) 0 0 var(--radius, 6px);
      margin-left: 0;
    }
    .seg button:last-child {
      border-radius: 0 var(--radius, 6px) var(--radius, 6px) 0;
    }
    .seg button[aria-pressed='true'] {
      background: color-mix(in srgb, var(--accent, #0066cc) 14%, var(--card, #fff));
      border-color: var(--accent, #0066cc);
      color: var(--accent, #0066cc);
      font-weight: 600;
      position: relative;
    }
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
      background: color-mix(in srgb, var(--accent, #0066cc) 12%, transparent);
      color: var(--fg, inherit);
    }
    .chip button {
      padding: 0 0.3rem;
      border: none;
      background: none;
      color: var(--muted, #6a6e73);
      font-size: 1rem;
      line-height: 1;
      border-radius: 999px;
      cursor: pointer;
    }
    .chip button:hover {
      color: var(--error, #c9190b);
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
    button.link {
      padding: 0;
      border: none;
      background: none;
      color: var(--accent, #0066cc);
      font-weight: 400;
      text-align: left;
    }
    button.link:hover {
      text-decoration: underline;
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
    .muted {
      color: var(--muted, #6a6e73);
    }
  `;

  @property({ attribute: false })
  form: FilterForm = undefined!;

  /** The form the rows shown were searched with: what the chips name. */
  @property({ attribute: false })
  appliedForm: FilterForm = undefined!;

  @property({ type: Boolean })
  busy = false;

  @property({ type: Boolean })
  copied = false;

  /** Completions per text filter, from the recorded values. */
  @state()
  private completions: Partial<Record<AuditValueField, string[]>> = {};

  private completionTimer?: ReturnType<typeof setTimeout>;

  private emitChange(form: FilterForm, when: AuditFilterChangeDetail['when'] = 'now'): void {
    this.dispatchEvent(
      new CustomEvent<AuditFilterChangeDetail>('filter-change', {
        detail: { form, when },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private choose(change: Partial<FilterForm>): void {
    this.emitChange({ ...this.form, ...change });
  }

  private clearFilters(): void {
    const { sort, order } = this.form;
    this.emitChange({
      caller: '',
      system: '',
      realm: '',
      tool: '',
      level: '',
      outcome: '',
      anonymous: '',
      sort,
      order,
      timeMode: 'any',
      agoValue: '1',
      agoUnit: 'hours',
      from: '',
      to: '',
    });
  }

  private onSubmit(e: Event): void {
    e.preventDefault();
    this.emitChange(this.form);
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
          const value = (e.target as HTMLInputElement).value;
          const next = { ...this.form, [field]: value };
          // a completion picked from the list, or the field emptied with its ×: no Enter needed
          if (value === '' || (this.completions[field] ?? []).includes(value)) {
            this.emitChange(next);
          } else {
            this.emitChange(next, 'draft');
            this.completeSoon(field, value);
          }
        }}
        @change=${(e: Event) => {
          const value = (e.target as HTMLInputElement).value;
          this.emitChange({ ...this.form, [field]: value });
        }}
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
        ${this.segmented('Time', TIME_MODES, mode, (timeMode: TimeMode) => this.choose({ timeMode }))}
        ${mode === 'ago'
          ? html`<input
                class="number"
                type="number"
                min="1"
                step="1"
                aria-label="How many"
                .value=${this.form.agoValue}
                @input=${(e: Event) => {
                  const agoValue = (e.target as HTMLInputElement).value;
                  this.emitChange({ ...this.form, agoValue }, 'soon');
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

  render() {
    const chips = chipsOf(this.appliedForm);
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
            @click=${() => this.dispatchEvent(new CustomEvent('copy-link', { bubbles: true, composed: true }))}
          >
            ${this.copied ? 'Copied' : 'Copy link'}
          </button>
          <button
            type="button"
            class="secondary"
            title="Load the newest events again"
            ?disabled=${this.busy}
            @click=${() => this.dispatchEvent(new CustomEvent('refresh', { bubbles: true, composed: true }))}
          >
            Refresh
          </button>
        </div>
      </form>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    'kc-mcp-audit-filter': AuditFilter;
  }
  interface HTMLElementEventMap {
    'filter-change': CustomEvent<AuditFilterChangeDetail>;
    'copy-link': CustomEvent<void>;
    refresh: CustomEvent<void>;
  }
}
