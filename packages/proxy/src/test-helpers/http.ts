/** Extracts the hidden `csrf_token` field from a rendered form. */
export function csrfFrom(html: string): string {
  const match = /name="csrf_token"\s+value="([^"]*)"/.exec(html);
  if (!match?.[1]) throw new Error("No csrf_token field in HTML");
  return match[1];
}

export interface CookieClient {
  fetch: (input: string, init?: RequestInit) => Promise<Response>;
  /** Current cookies as name -> raw (still URL-encoded) value. */
  cookies: Map<string, string>;
}

/** `fetch` with a cookie jar. Redirects are NOT followed by default so tests
 * can assert on `Location`; pass `redirect: "follow"` to override. Single
 * host, no path/expiry matching beyond honouring deletion (Max-Age=0 / past Expires). */
export function cookieClient(): CookieClient {
  const cookies = new Map<string, string>();
  return {
    cookies,
    async fetch(input, init = {}) {
      const headers = new Headers(init.headers);
      if (cookies.size > 0) {
        headers.set("cookie", [...cookies].map(([k, v]) => `${k}=${v}`).join("; "));
      }
      const res = await fetch(input, { redirect: "manual", ...init, headers });
      for (const line of res.headers.getSetCookie()) {
        const [pair, ...attrs] = line.split(";").map((s) => s.trim());
        const eq = pair!.indexOf("=");
        const name = pair!.slice(0, eq);
        const value = pair!.slice(eq + 1);
        const lower = attrs.map((a) => a.toLowerCase());
        const expired =
          lower.includes("max-age=0") ||
          lower.some((a) => a.startsWith("expires=") && Date.parse(a.slice(8)) <= Date.now());
        if (expired || value === "") cookies.delete(name);
        else cookies.set(name, value);
      }
      return res;
    },
  };
}

/** Encodes an object as an application/x-www-form-urlencoded fetch body. */
export function form(fields: Record<string, string>): { body: string; headers: Record<string, string> } {
  return { body: new URLSearchParams(fields).toString(), headers: { "content-type": "application/x-www-form-urlencoded" } };
}
