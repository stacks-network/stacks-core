import fc from 'fast-check';
import { expect, it } from 'vitest';
import { pox5, serializeLockupScript } from './pox-5-helpers';
import { rov, rovOk } from '@clarigen/test';
import * as BTC from '@scure/btc-signer';
import { hex } from '@scure/base';
import { randomPrincipalGen } from '../test-helpers';

const maxCScriptNum = 549755813887n;

const cScriptNumBoundaryCases = [
  [0n, ''],
  [1n, '01'],
  [16n, '10'],
  [17n, '11'],
  [127n, '7f'],
  [128n, '8000'],
  [255n, 'ff00'],
  [256n, '0001'],
  [32767n, 'ff7f'],
  [32768n, '008000'],
  [65535n, 'ffff00'],
  [65536n, '000001'],
  [8388607n, 'ffff7f'],
  [8388608n, '00008000'],
  [16777215n, 'ffffff00'],
  [16777216n, '00000001'],
  [2147483647n, 'ffffff7f'],
  [2147483648n, '0000008000'],
  [4294967295n, 'ffffffff00'],
  [4294967296n, '0000000001'],
  [maxCScriptNum, 'ffffffff7f'],
] as const;

function btcScriptNumber(n: bigint) {
  const script = BTC.Script.encode([Number(n)]);
  const byteLength = script[0];
  return script.slice(1, byteLength + 1);
}

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

it('cscriptnum helpers match expected boundary vectors and scure encodings', () => {
  for (const [n, expected] of cScriptNumBoundaryCases) {
    expect(hex.encode(rovOk(pox5.serializeCScriptNum(n)))).toEqual(expected);
    if (n > 16n) {
      expect(hex.encode(rovOk(pox5.serializeCScriptNum(n)))).toEqual(
        hex.encode(btcScriptNumber(n)),
      );
    }
    const expectedPush = BTC.Script.encode([Number(n)]);
    expect(hex.encode(rovOk(pox5.pushCScriptNum(n)))).toEqual(
      hex.encode(expectedPush),
    );
  }
});

it('serialize-c-script-num matches scure script-number payloads for all valid large values', () => {
  fc.assert(
    fc.property(fc.bigInt({ min: 17n, max: maxCScriptNum }), (n) => {
      expect(hex.encode(rovOk(pox5.serializeCScriptNum(n)))).toEqual(
        hex.encode(btcScriptNumber(n)),
      );
    }),
  );
});

it('push-c-script-num matches scure script-number pushes for all valid values', () => {
  fc.assert(
    fc.property(fc.bigInt({ min: 0n, max: maxCScriptNum }), (n) => {
      const expected = BTC.Script.encode([Number(n)]);
      expect(hex.encode(rovOk(pox5.pushCScriptNum(n)))).toEqual(
        hex.encode(expected),
      );
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
  const minimumUnlockHeight = rov(pox5.getBondL1UnlockHeight(0n));

  fc.assert(
    fc.property(
      randomPrincipalGen,
      fc.bigInt({
        min: 0n,
        max: maxCScriptNum - minimumUnlockHeight,
      }),
      fc.uint8Array({ minLength: 1, maxLength: 255 }),
      fc.uint8Array({ minLength: 1, maxLength: 255 }),
      (stacker, offset, stakerUnlockBytes, earlyUnlockBytes) => {
        const unlockBurnHeight = minimumUnlockHeight + offset;
        const expected = serializeLockupScript({
          stacker,
          unlockBurnHeight,
          stakerUnlockBytes,
          earlyUnlockBytes,
        });
        const actual = rovOk(
          pox5.constructLockupScript(
            stacker,
            unlockBurnHeight,
            stakerUnlockBytes,
            earlyUnlockBytes,
          ),
        );

        expect(hex.encode(actual)).toEqual(hex.encode(expected));
      },
    ),
  );
});
