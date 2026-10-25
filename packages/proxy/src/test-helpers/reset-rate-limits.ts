import { beforeEach } from "vitest";
import { resetRateLimiters } from "../rate-limit.js";

// The per-IP request limiters are module state and every test client shares one
// loopback address, so each test starts with empty windows. Tests of the
// limits themselves fill them from here.
beforeEach(() => resetRateLimiters());
