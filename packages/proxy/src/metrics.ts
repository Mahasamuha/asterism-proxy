// Minimal in-memory metrics registry — counters plus simple sum/count pairs
// for latency (an average, not a full histogram; percentiles would need a
// real metrics library, which is more than this proxy's single-instance
// operational needs justify right now). No persistence: metrics reset on
// restart, same tradeoff already accepted for every other in-memory cache
// in this codebase (T8, T16, T17).

type Labels = Record<string, string>;

function keyOf(name: string, labels?: Labels): string {
  if (!labels || Object.keys(labels).length === 0) return name;
  const labelStr = Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join(",");
  return `${name}{${labelStr}}`;
}

const counters = new Map<string, number>();
const durationSums = new Map<string, number>();
const durationCounts = new Map<string, number>();

export function incrementCounter(name: string, labels?: Labels, by = 1): void {
  const key = keyOf(name, labels);
  counters.set(key, (counters.get(key) ?? 0) + by);
}

export function recordDuration(name: string, labels: Labels, ms: number): void {
  const key = keyOf(name, labels);
  durationSums.set(key, (durationSums.get(key) ?? 0) + ms);
  durationCounts.set(key, (durationCounts.get(key) ?? 0) + 1);
}

export function snapshotMetrics(): {
  counters: Record<string, number>;
  durations: Record<string, { count: number; sumMs: number; avgMs: number }>;
} {
  const durations: Record<string, { count: number; sumMs: number; avgMs: number }> = {};
  for (const [key, count] of durationCounts) {
    const sumMs = durationSums.get(key) ?? 0;
    durations[key] = { count, sumMs, avgMs: count > 0 ? sumMs / count : 0 };
  }
  return { counters: Object.fromEntries(counters), durations };
}
