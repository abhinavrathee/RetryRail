/**
 * Blade 12.121.0 expects ts-deepmerge's removed default export. The workspace
 * redirects that import here so it can use the advisory-fixed v8 named export.
 */
export { merge as default } from 'ts-deepmerge-secure';

