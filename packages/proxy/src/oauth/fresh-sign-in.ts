import type { ResourceServer } from "../resource-registry.js";

/** True when any of the requested scopes needs a fresh sign-in, per the
 * registry's current view of the server. A missing server has none: the flow
 * fails on the unregistered resource anyway. */
export function requestsFreshSignIn(server: ResourceServer | undefined, scopes: readonly string[]): boolean {
  if (!server) return false;
  return scopes.some((name) => server.scopes.some((s) => s.name === name && s.freshSignIn));
}
