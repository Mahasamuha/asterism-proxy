import pino from "pino";

export const logger = pino({
  level: process.env["LOG_LEVEL"] ?? "warn",
  redact: {
    paths: ["token", "auth", "password", "secret", "*.token", "*.auth", "*.password", "*.secret", "err.path"],
    censor: "[REDACTED]",
  },
});

export function createLogger(name: string) {
  return logger.child({ module: name });
}
