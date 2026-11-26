// Shared ESLint config for every JS/TS package (CLAUDE.md conventions and security rules).
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/node_modules/**", "**/.wrangler/**", "**/.cloudflare/**", "apps/web/src/wasm/**", "target/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // Secrets must never reach the console (R-SEC-1).
      "no-console": "error",
      // All randomness comes from crypto.getRandomValues (crypto design §9).
      "no-restricted-properties": [
        "error",
        { object: "Math", property: "random", message: "Use crypto.getRandomValues; see cryptographic-design.md §9." },
      ],
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
  {
    files: ["apps/web/**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    languageOptions: { globals: globals.browser },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Idiomatic React handlers (`onClick={() => setX(v)}`) return the setter's void.
      "@typescript-eslint/no-confusing-void-expression": ["error", { ignoreArrowShorthand: true, ignoreVoidReturningFunctions: true }],
      // CSS-module class names are typed `string | undefined` under noUncheckedIndexedAccess.
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true, allowNullish: true }],
      // Data-loading effects set state after an await; that is the intended pattern here.
      "react-hooks/set-state-in-effect": "off",
      // Item data must never be rendered as HTML (threat model T-25).
      "no-restricted-syntax": [
        "error",
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "Never render HTML from data (threat model T-25)." },
      ],
    },
  },
  {
    // Tests parse JSON responses dynamically; keep src strict, relax only unsafe-any in tests.
    files: ["**/test/**/*.ts", "**/*.test.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/restrict-template-expressions": "off",
    },
  },
  {
    files: ["**/*.config.{js,ts}", "eslint.config.js"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: { globals: globals.node },
  },
);
