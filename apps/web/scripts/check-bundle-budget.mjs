/* global console */
import { readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';

const assetsDirectory = resolve(import.meta.dirname, '..', 'dist', 'assets');
const javaScriptAssets = readdirSync(assetsDirectory)
  .filter((name) => name.endsWith('.js'))
  .map((name) => ({ name, bytes: statSync(resolve(assetsDirectory, name)).size }));

const entry = javaScriptAssets.find(({ name }) => name.startsWith('index-'));
const blade = javaScriptAssets.find(({ name }) => name.startsWith('AppRoot-'));
const totalBytes = javaScriptAssets.reduce((total, asset) => total + asset.bytes, 0);
const limits = {
  entry: 200_000,
  blade: 800_000,
  total: 1_000_000,
};

const failures = [
  entry === undefined ? 'entry chunk was not found' : undefined,
  blade === undefined ? 'lazy Blade chunk was not found' : undefined,
  entry !== undefined && entry.bytes > limits.entry
    ? `entry chunk ${entry.bytes} exceeds ${limits.entry} bytes`
    : undefined,
  blade !== undefined && blade.bytes > limits.blade
    ? `Blade chunk ${blade.bytes} exceeds ${limits.blade} bytes`
    : undefined,
  totalBytes > limits.total ? `total JavaScript ${totalBytes} exceeds ${limits.total} bytes` : undefined,
].filter(Boolean);

if (failures.length > 0) {
  throw new Error(`Bundle budget failed:\n- ${failures.join('\n- ')}`);
}

console.log(
  `Bundle budget passed: entry=${entry.bytes}B Blade=${blade.bytes}B total=${totalBytes}B`,
);
