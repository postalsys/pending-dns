'use strict';

const { FlatCompat } = require('@eslint/eslintrc');
const js = require('@eslint/js');
const prettier = require('eslint-config-prettier');

const compat = new FlatCompat({
    baseDirectory: __dirname,
    recommendedConfig: js.configs.recommended,
    allConfig: js.configs.all
});

module.exports = [
    {
        ignores: ['node_modules/', 'ee-dist/', 'coverage/', 'views/', '.prettierrc.js']
    },

    // Shared Nodemailer ESLint rules (eslintrc format, wrapped for flat config)
    ...compat.extends('eslint-config-nodemailer'),

    // Disable stylistic rules that conflict with Prettier
    prettier,

    {
        languageOptions: {
            ecmaVersion: 2023,
            sourceType: 'commonjs'
        },
        rules: {
            indent: 'off',
            'no-await-in-loop': 'off',
            'require-atomic-updates': 'off',
            // Preserve the long-standing project convention of `catch (err) { /* ignore */ }`.
            // ESLint 9 changed the no-unused-vars `caughtErrors` default to 'all'.
            'no-unused-vars': ['error', { caughtErrors: 'none' }]
        }
    }
];
