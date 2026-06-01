import fc from 'fast-check';
import { expect, it } from 'vitest';
import { pox5, serializeLockupScript } from './pox-5-helpers';
import { rov } from '@clarigen/test';
import * as BTC from '@scure/btc-signer';
import { hex } from '@scure/base';
import { randomPrincipalGen } from '../test-helpers';

it('uint-to-buff-le matches little-endian encoding for all n < 65536', () => {
  fc.assert(
    fc.property(fc.integer({ min: 0, max: 0xffff }), (n) => {
      const actual = rov(pox5.uintToBuffLe(n));
      const expected =
        n < 256
          ? new Uint8Array([n])
          : new Uint8Array([n & 0xff, (n >> 8) & 0xff]);
      expect(hex.encode(actual)).toEqual(hex.encode(expected));
    }),
  );
});

it('should correctly prefix a script based on length', () => {
  fc.assert(
    fc.property(
      fc.uint8Array({
        minLength: 1,
        maxLength: 0xfffe,
      }),
      (bytes) => {
        const expected = BTC.Script.encode([bytes]);
        const actual = rov(pox5.pushScriptBytes(bytes));
        expect(hex.encode(actual)).toEqual(hex.encode(expected));
      },
    ),
  );
});

it('should construct the unlock script', () => {
  fc.assert(
    fc.property(
      randomPrincipalGen,
      fc.integer({ min: 1, max: 0x7fffff }),
      fc.uint8Array({ minLength: 1, maxLength: 255 }),
      fc.uint8Array({ minLength: 1, maxLength: 255 }),
      (stacker, unlockBurnHeight, unlockBytes, earlyUnlockBytes) => {
        const expected = serializeLockupScript({
          stacker,
          unlockBurnHeight: BigInt(unlockBurnHeight),
          unlockBytes,
          earlyUnlockBytes,
        });
        const actual = rov(
          pox5.constructLockupScript(
            stacker,
            unlockBurnHeight,
            unlockBytes,
            earlyUnlockBytes,
          ),
        );

        expect(hex.encode(actual)).toEqual(hex.encode(expected));
      },
    ),
  );
});
