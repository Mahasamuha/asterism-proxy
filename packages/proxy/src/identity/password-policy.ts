export const MIN_PASSWORD_LENGTH = 12;
/** bcrypt only reads the first 72 BYTES of its input and silently ignores the
 * rest, so a longer password would be "accepted" while only its prefix counted.
 * Refuse it instead. This is bytes (UTF-8), not characters: "é" is two. */
export const MAX_PASSWORD_BYTES = 72;

/** Why `password` can't be used, as a phrase that follows "Password " (null if it is fine). */
export function passwordProblem(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `must be at least ${MIN_PASSWORD_LENGTH} characters`;
  const bytes = Buffer.byteLength(password, "utf8");
  if (bytes > MAX_PASSWORD_BYTES) {
    return `must be at most ${MAX_PASSWORD_BYTES} bytes when UTF-8 encoded (this one is ${bytes} bytes; non-ASCII characters take 2-4 bytes each)`;
  }
  return null;
}
