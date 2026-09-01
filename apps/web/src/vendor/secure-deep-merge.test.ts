import { describe, expect, it } from 'vitest';

import secureMerge from './secure-deep-merge';

describe('secure Blade merge adapter', () => {
  it('retains ordinary theme keys while dropping prototype override keys', () => {
    const untrustedShape = JSON.parse(
      '{"colors":{"primary":"#265cf6"},"__proto__":{"polluted":true},"constructor":{"polluted":true}}',
    ) as Record<string, unknown>;

    const merged = secureMerge({ spacing: { small: 8 } }, untrustedShape);

    expect(merged).toEqual({
      colors: { primary: '#265cf6' },
      spacing: { small: 8 },
    });
    expect(Object.prototype).not.toHaveProperty('polluted');
  });
});

