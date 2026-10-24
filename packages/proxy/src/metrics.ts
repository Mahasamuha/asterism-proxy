// Minimal in-memory metrics registry — counters plus simple sum/count pairs
// for latency (exposed as a Prometheus summary without quantiles; percentiles
// would need a real metrics library, which is more than this proxy's
// single-instance operational needs justify right now). No persistence:
// metrics reset on restart, same tradeoff already accepted for every other
// in-memory cache in this codebase (T8, T16, T17).
//
// Series keep their labels as structured data (not a flattened "k=v" string)
// so renderPrometheus() can emit them with proper escaping.

type Labels = Record<string, string>;

interface Series {
  labels: Labels;
  value: number; // counter value, or duration sum in ms
  count: number; // duration observations (unused for counters)
}

// metric name -> serialized labels -> series
const counters = new Map<string, Map<string, Series>>();
const durations = new Map<string, Map<string, Series>>();

function labelsKey(labels: Labels): string {
  return JSON.stringify(Object.entries(labels).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

function seriesFor(registry: Map<string, Map<string, Series>>, name: string, labels: Labels): Series {
  let bySeries = registry.get(name);
  if (!bySeries) {
    bySeries = new Map();
    registry.set(name, bySeries);
  }
  const key = labelsKey(labels);
  let series = bySeries.get(key);
  if (!series) {
    series = { labels: { ...labels }, value: 0, count: 0 };
    bySeries.set(key, series);
  }
  return series;
}

export function incrementCounter(name: string, labels: Labels = {}, by = 1): void {
  seriesFor(counters, name, labels).value += by;
}

export function recordDuration(name: string, labels: Labels, ms: number): void {
  const series = seriesFor(durations, name, labels);
  series.value += ms;
  series.count += 1;
}

// ---------------------------------------------------------------------------
// Prometheus text exposition format 0.0.4
// ---------------------------------------------------------------------------

export const PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

const HELP: Record<string, string> = {
  refresh_reuse_detected_total: "Refresh token or authorization code replays that triggered descendant revocation.",
  tokens_issued_total: "Access tokens issued.",
  device_flow_outcomes_total: "Terminal outcomes of device authorization flows.",
  consent_total: "Consent decisions.",
  local_login_failures_total: "Failed local account logins.",
  cimd_fetch_total: "Client ID metadata document fetches by outcome.",
  cimd_fetch_duration_ms: "Client ID metadata document fetch duration in milliseconds.",
  ssrf_rejections_total: "Outbound fetches rejected by the SSRF guard, by reason.",
};

/** Coerces a name to the Prometheus metric/label name charset [a-zA-Z_][a-zA-Z0-9_]*. */
function sanitizeName(name: string): string {
  const cleaned = name.replace(/[^a-zA-Z0-9_]/g, "_");
  return /^[a-zA-Z_]/.test(cleaned) ? cleaned : `_${cleaned}`;
}

/** Label values: backslash, double quote and newline must be escaped. */
function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

function escapeHelp(text: string): string {
  return text.replace(/\\/g, "\\\\").replace(/\n/g, "\\n");
}

function formatLabels(labels: Labels): string {
  const parts = Object.entries(labels)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${sanitizeName(k)}="${escapeLabelValue(v)}"`);
  return parts.length > 0 ? `{${parts.join(",")}}` : "";
}

function helpLine(rawName: string, name: string): string {
  return `# HELP ${name} ${escapeHelp(HELP[rawName] ?? rawName.replace(/_/g, " "))}`;
}

/** Counters from outside the registry (e.g. the SSRF guard keeps its own tallies),
 * keyed by metric name, then by label set. */
export type ExternalCounters = Record<string, Array<{ labels: Labels; value: number }>>;

export function renderPrometheus(external: ExternalCounters = {}): string {
  const lines: string[] = [];

  const allCounters = new Map<string, Array<{ labels: Labels; value: number }>>();
  for (const [name, bySeries] of counters) allCounters.set(name, [...bySeries.values()]);
  for (const [name, series] of Object.entries(external)) {
    allCounters.set(name, [...(allCounters.get(name) ?? []), ...series]);
  }

  for (const [rawName, series] of [...allCounters].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const safe = sanitizeName(rawName);
    const name = safe.endsWith("_total") ? safe : `${safe}_total`;
    lines.push(helpLine(rawName, name), `# TYPE ${name} counter`);
    for (const s of series) lines.push(`${name}${formatLabels(s.labels)} ${s.value}`);
  }

  for (const [rawName, bySeries] of [...durations].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const name = sanitizeName(rawName);
    lines.push(helpLine(rawName, name), `# TYPE ${name} summary`);
    for (const s of bySeries.values()) {
      const labels = formatLabels(s.labels);
      lines.push(`${name}_sum${labels} ${s.value}`, `${name}_count${labels} ${s.count}`);
    }
  }

  return lines.length > 0 ? `${lines.join("\n")}\n` : "";
}
