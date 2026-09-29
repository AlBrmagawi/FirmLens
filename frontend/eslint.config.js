import js from "@eslint/js";
import ts from "typescript-eslint";
import hooks from "eslint-plugin-react-hooks";
import globals from "globals";
export default ts.config(
  {
    ignores: [
      "dist",
      "playwright-report",
      "test-results",
      "src/generated.ts",
      "public/vendor",
    ],
  },
  js.configs.recommended,
  { files: ["public/*.js"], languageOptions: { globals: globals.browser } },
  ...ts.configs.recommended,
  {
    files: ["scripts/*.mjs"],
    languageOptions: { globals: { ...globals.node, ...globals.browser } },
  },
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
    plugins: { "react-hooks": hooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",
    },
  },
);
