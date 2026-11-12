import type { AuditFilter, AuditValueField } from '../../bff.js';

/** Fields of the filter form; times as the `datetime-local` inputs give them (local time, no zone). */
export type FilterForm = {
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
export const AGO_UNITS = {
  minutes: 60_000,
  hours: 3_600_000,
  days: 86_400_000,
  weeks: 604_800_000,
} as const;

export type AgoUnit = keyof typeof AGO_UNITS;

export type TimeMode = 'any' | 'ago' | 'range';

export type SortBy = 'when' | 'took' | 'caller';

/** The direction a column starts with: newest and slowest first, names from A. */
export const FIRST_ORDER: Record<SortBy, 'asc' | 'desc'> = { when: 'desc', took: 'desc', caller: 'asc' };

export const CALLERS = [
  { value: '', label: 'All' },
  { value: 'exclude', label: 'Signed in' },
  { value: 'only', label: 'Anonymous' },
] as const;

export const LEVELS = [
  { value: '', label: 'All' },
  { value: 'READ', label: 'Read' },
  { value: 'WRITE', label: 'Write' },
  { value: 'DESTRUCTIVE', label: 'Destructive' },
] as const;

export const OUTCOMES = [
  { value: '', label: 'All' },
  { value: 'ok', label: 'OK' },
  { value: 'error', label: 'Refused or failed' },
] as const;

export const TIME_MODES: { value: TimeMode; label: string }[] = [
  { value: 'any', label: 'Any time' },
  { value: 'ago', label: 'Last …' },
  { value: 'range', label: 'Between …' },
];

export const TEXT_FIELDS: { field: AuditValueField; label: string; placeholder: string }[] = [
  { field: 'caller', label: 'Caller', placeholder: 'any caller' },
  { field: 'system', label: 'System', placeholder: 'any system' },
  { field: 'realm', label: 'Realm', placeholder: 'any realm' },
  { field: 'tool', label: 'Tool', placeholder: 'any tool' },
];

export const EMPTY: FilterForm = {
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
export const PAGE_SIZES = [25, 50, 100, 250] as const;

/** Units of "last ..." as the letter the query string uses (`last=2w`). */
const UNIT_LETTERS: Record<AgoUnit, string> = { minutes: 'm', hours: 'h', days: 'd', weeks: 'w' };

/** How long ago a moment was, next to the exact instant ("4 minutes ago"). */
export function timeAgo(instant: string): string {
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

/**
 * The filters as query parameters: `system`, `realm`, `tool`, `level`, `outcome`, `last` (`90m`, `2w`) or `from` /
 * `to` (ISO-8601 instants, so a link means the same moment in every time zone) and `size`. Defaults are left out;
 * the caller always is.
 */
export function toQuery(form: FilterForm, pageSize: number): URLSearchParams {
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
export function fromQuery(q: URLSearchParams): { form: FilterForm; pageSize: number } {
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
export function agoInstant(value: string, unit: AgoUnit): string | undefined {
  const n = Number(value);
  if (!value || !Number.isFinite(n) || n <= 0) {
    return undefined;
  }
  return new Date(Date.now() - n * AGO_UNITS[unit]).toISOString();
}

/** A `datetime-local` value (local time) as an ISO-8601 instant; empty stays unset. */
export function toInstant(local: string): string | undefined {
  if (!local) {
    return undefined;
  }
  const date = new Date(local);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/** Builds the API filter from the form; `limit` is the page size. */
export function filterOf(form: FilterForm, pageSize: number): AuditFilter {
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
    limit: pageSize,
  };
}

/** Applied filters as chips: each with a partial form that removes that filter. */
export function chipsOf(f: FilterForm): { label: string; without: Partial<FilterForm> }[] {
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
