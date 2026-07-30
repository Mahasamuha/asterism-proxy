import pino from "pino";
import { config } from "./config.js";

export const logger = pino({
  level: config.logLevel,
  redact: {
    paths: ["token", "auth", "password", "secret", "privateJwk", "*.token", "*.auth", "*.password", "*.secret", "*.privateJwk", "err.path"],
    censor: "[REDACTED]",
  },
});

export function createLogger(name: string) {
  return logger.child({ module: name });
}
