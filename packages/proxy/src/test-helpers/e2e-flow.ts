import { csrfFrom, form, type CookieClient } from "./http.js";

export const E2E_RESOURCE = "https://mcp.example.test/mcp";
export const E2E_REDIRECT_URI = "https://client.example.test/cb";
export const E2E_USERNAME = "e2e-admin";
export const E2E_PASSWORD = "e2e correct horse battery";

/** The Location header of a redirect, resolved against the app's base URL. */
export function locationOf(res: Response, baseUrl: string): URL {
  const location = res.headers.get("location");
  if (!location) throw new Error(`Expected a redirect, got ${res.status}`);
  return new URL(location, baseUrl);
}

/** GET /setup then POST it with the CSRF token; leaves the session cookie in the jar. */
export async function setupFirstAccount(browser: CookieClient, baseUrl: string): Promise<void> {
  const page = await browser.fetch(`${baseUrl}/setup`);
  const csrf = csrfFrom(await page.text());
  const res = await browser.fetch(`${baseUrl}/setup`, {
    method: "POST",
    ...form({ csrf_token: csrf, username: E2E_USERNAME, password: E2E_PASSWORD, confirm_password: E2E_PASSWORD }),
  });
  if (res.status !== 302) throw new Error(`/setup failed with ${res.status}`);
}

/** Follows a `/auth/login?flow=` redirect: renders the form, submits credentials, returns the next Location. */
export async function loginForFlow(browser: CookieClient, baseUrl: string, loginUrl: URL): Promise<URL> {
  const flow = loginUrl.searchParams.get("flow");
  if (!flow) throw new Error("login URL has no flow");
  const page = await browser.fetch(loginUrl.toString());
  const csrf = csrfFrom(await page.text());
  const res = await browser.fetch(`${baseUrl}/auth/login`, {
    method: "POST",
    ...form({ csrf_token: csrf, flow, username: E2E_USERNAME, password: E2E_PASSWORD }),
  });
  return locationOf(res, baseUrl);
}

/** Renders the consent page at `consentUrl` and submits approve or deny. Returns the raw response. */
export async function submitConsent(browser: CookieClient, baseUrl: string, consentUrl: URL, action: "approve" | "deny"): Promise<Response> {
  const flow = consentUrl.searchParams.get("flow");
  if (!flow) throw new Error("consent URL has no flow");
  const page = await browser.fetch(consentUrl.toString());
  if (page.status !== 200) throw new Error(`consent page returned ${page.status}`);
  const csrf = csrfFrom(await page.text());
  return browser.fetch(`${baseUrl}/oauth/consent`, { method: "POST", ...form({ csrf_token: csrf, flow, action }) });
}
