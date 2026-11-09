import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

/**
 * Security guardrails: the scanner must never become the exfiltration
 * mechanism it is designed to detect. Network, persistence and raw-HTML APIs
 * are banned in application code via lint rules (tests are exempt so they can
 * spy on these APIs and prove they are never used).
 */
const securityRules = {
  'no-restricted-globals': [
    'error',
    { name: 'fetch', message: 'Network calls are forbidden in this frontend-only scanner.' },
    { name: 'XMLHttpRequest', message: 'Network calls are forbidden.' },
    { name: 'WebSocket', message: 'Network calls are forbidden.' },
    { name: 'EventSource', message: 'Network calls are forbidden.' },
    { name: 'localStorage', message: 'Prompts must not be persisted.' },
    { name: 'sessionStorage', message: 'Prompts must not be persisted.' },
    { name: 'indexedDB', message: 'Prompts must not be persisted.' },
  ],
  'no-restricted-properties': [
    'error',
    { object: 'navigator', property: 'sendBeacon', message: 'Network calls are forbidden.' },
    { object: 'document', property: 'cookie', message: 'Prompts must not be persisted.' },
    { object: 'window', property: 'fetch', message: 'Network calls are forbidden.' },
    { object: 'window', property: 'localStorage', message: 'Prompts must not be persisted.' },
    { object: 'window', property: 'sessionStorage', message: 'Prompts must not be persisted.' },
    {
      object: 'window',
      property: 'open',
      message: 'Navigation to submitted content is forbidden.',
    },
  ],
  'no-restricted-syntax': [
    'error',
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: 'dangerouslySetInnerHTML is forbidden; render user content as text.',
    },
    {
      selector: 'MemberExpression[property.name=/^(innerHTML|outerHTML|insertAdjacentHTML)$/]',
      message: 'Raw HTML APIs are forbidden; render user content as text.',
    },
  ],
  'no-eval': 'error',
  'no-new-func': 'error',
};

export default tseslint.config(
  { ignores: ['dist', 'coverage', '.playwright-mcp', 'node_modules'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.strictTypeChecked],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      ...securityRules,
    },
  },
  {
    files: ['src/**/*.test.{ts,tsx}', 'src/test/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-globals': 'off',
      'no-restricted-properties': 'off',
      'no-restricted-syntax': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/unbound-method': 'off',
      '@typescript-eslint/no-empty-function': 'off',
    },
  },
);
