import type { ClientSource, TrustLevel } from "../generated/prisma/client.js";

// Full config-driven allowlist/denylist policy lands in T11. Until then, this
// implements just its stated fallback rule: any resolved CIMD document gets
// domain_verified, DCR registrations get unverified — T11 layers the exact-id
// and domain allowlists (-> allowlisted) on top of this.
export function assignTrustLevel(source: ClientSource): TrustLevel {
  return source === "cimd" ? "domain_verified" : "unverified";
}
