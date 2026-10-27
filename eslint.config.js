import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/dist/**", "**/node_modules/**", "**/src/generated/**"] },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    rules: {
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "no-console": "warn",
      // Errors reach the logs only as `err`, so the logger's serializer (logger.ts)
      // picks the fields. Any other spelling skips it and can log a response body,
      // headers or query arguments.
      "no-restricted-syntax": [
        "error",
        {
          selector: `CallExpression[callee.object.name=/^(log|logger)$/] > ObjectExpression > Property[key.name=/^(error|cause|e)$/]`,
          message: "Log errors as `{ err }` so the logger's serializer applies; `error`, `cause` and `e` keys bypass it.",
        },
        {
          selector: `CallExpression[callee.object.name=/^(log|logger)$/] > ObjectExpression > Property[key.value=/^(error|cause|e)$/]`,
          message: "Log errors as `{ err }` so the logger's serializer applies; `error`, `cause` and `e` keys bypass it.",
        },
        {
          selector: `CallExpression[callee.object.name=/^(log|logger)$/] > ObjectExpression > Property[key.name="err"]:not([value.type="Identifier"])`,
          message: "Log errors as `{ err }` so the logger's serializer applies; do not pass `err: <expression>` (e.g. err.message).",
        },
      ],
    },
  },
);
