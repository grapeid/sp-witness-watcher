import { describe, expect, it } from 'vitest';
import { kelDigestAtSeq } from './digest.js';

/** Golden value from Go: go run ./scripts/golden-digest/ */
const GO_GOLDEN_DIGEST = 'EIL7184M0CepkyBvLnW5amSFHgSSmRTLCHfmEMsFL8l-';

describe('kelDigestAtSeq', () => {
  it('matches Go Blake3 Matter qb64 output', () => {
    const ev = {
      v: 'KERI10JSON000256_',
      t: 'icp',
      i: 'EAlice',
      s: '0',
      k: ['Dkey1'],
    };
    expect(kelDigestAtSeq([ev], 0)).toBe(GO_GOLDEN_DIGEST);
  });
});
