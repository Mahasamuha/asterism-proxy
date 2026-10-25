import { beforeEach, describe, expect, it, vi } from "vitest";

type Metrics = typeof import("./metrics.js");
let m: Metrics;

beforeEach(async () => {
  vi.resetModules();
  m = await import("./metrics.js");
});

describe("renderPrometheus", () => {
  it("renders nothing when empty", () => {
    expect(m.renderPrometheus()).toBe("");
  });

  it("appends _total to counter names that lack it, and not twice", () => {
    m.incrementCounter("things");
    m.incrementCounter("tokens_issued_total");
    const out = m.renderPrometheus();
    expect(out).toContain("# TYPE things_total counter");
    expect(out).toContain("things_total 1");
    expect(out).toContain("# TYPE tokens_issued_total counter");
    expect(out).not.toContain("_total_total");
  });

  it("accumulates and separates series by label set (order-insensitive)", () => {
    m.incrementCounter("c_total", { a: "1", b: "2" });
    m.incrementCounter("c_total", { b: "2", a: "1" }, 4);
    m.incrementCounter("c_total", { a: "other" });
    const out = m.renderPrometheus();
    expect(out).toContain('c_total{a="1",b="2"} 5');
    expect(out).toContain('c_total{a="other"} 1');
  });

  it("escapes backslash, quote and newline in label values", () => {
    m.incrementCounter("e_total", { client_id: 'https://a"b\\c\nd.example/x' });
    expect(m.renderPrometheus()).toContain('e_total{client_id="https://a\\"b\\\\c\\nd.example/x"} 1');
  });

  it("sanitizes metric and label names to the Prometheus charset", () => {
    m.incrementCounter("weird-name.x", { "bad-label": "v" });
    m.incrementCounter("9starts", { "1lab": "v" });
    const out = m.renderPrometheus();
    expect(out).toContain('weird_name_x_total{bad_label="v"} 1');
    expect(out).toContain('_9starts_total{_1lab="v"} 1');
  });

  it("emits HELP then TYPE, with known help text and a fallback", () => {
    m.incrementCounter("tokens_issued_total");
    m.incrementCounter("custom_thing_total");
    const out = m.renderPrometheus();
    expect(out).toContain("# HELP tokens_issued_total Access tokens issued.\n# TYPE tokens_issued_total counter\n");
    expect(out).toContain("# HELP custom_thing_total custom thing total\n");
  });

  it("renders durations as a summary with _sum and _count", () => {
    m.recordDuration("cimd_fetch_duration_ms", { outcome: "success" }, 12.5);
    m.recordDuration("cimd_fetch_duration_ms", { outcome: "success" }, 7.5);
    m.recordDuration("cimd_fetch_duration_ms", { outcome: "failure" }, 3);
    const out = m.renderPrometheus();
    expect(out).toContain("# TYPE cimd_fetch_duration_ms summary");
    expect(out).toContain('cimd_fetch_duration_ms_sum{outcome="success"} 20');
    expect(out).toContain('cimd_fetch_duration_ms_count{outcome="success"} 2');
    expect(out).toContain('cimd_fetch_duration_ms_count{outcome="failure"} 1');
    expect(out).not.toContain("cimd_fetch_duration_ms_total");
  });

  it("merges external counters with registry counters of the same name", () => {
    m.incrementCounter("ssrf_rejections_total", { reason: "timeout" });
    const out = m.renderPrometheus({
      ssrf_rejections_total: [{ labels: { reason: "blocked_address" }, value: 3 }],
      other: [{ labels: {}, value: 2 }],
    });
    expect(out).toContain('ssrf_rejections_total{reason="timeout"} 1');
    expect(out).toContain('ssrf_rejections_total{reason="blocked_address"} 3');
    expect(out).toContain("other_total 2");
    expect(out.match(/# TYPE ssrf_rejections_total/g)).toHaveLength(1);
  });

  it("is sorted by metric name and ends with a newline", () => {
    m.incrementCounter("zzz_total");
    m.incrementCounter("aaa_total");
    const out = m.renderPrometheus();
    expect(out.indexOf("aaa_total")).toBeLessThan(out.indexOf("zzz_total"));
    expect(out.endsWith("\n")).toBe(true);
  });

  it("exposes the exposition content type", () => {
    expect(m.PROMETHEUS_CONTENT_TYPE).toBe("text/plain; version=0.0.4; charset=utf-8");
  });
});
