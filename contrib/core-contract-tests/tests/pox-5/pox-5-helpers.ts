import * as BTC from '@scure/btc-signer';
import { createAddress } from '@stacks/transactions';
import { hex } from '@scure/base';

export function toWitnessOutput(script: Uint8Array) {
  return BTC.OutScript.encode(
    BTC.p2wsh({
      type: 'wsh',
      script,
    }),
  );
}

export function serializeLockupScript({
  stacker,
  unlockBurnHeight,
  unlockBytes,
}: {
  stacker: string;
  unlockBurnHeight: bigint;
  unlockBytes: Uint8Array;
}) {
  const addr = createAddress(stacker);
  return BTC.Script.encode([
    new Uint8Array([5, addr.version, ...hex.decode(addr.hash160)]),
    'DROP',
    Number(unlockBurnHeight),
    'CHECKLOCKTIMEVERIFY',
    'DROP',
    unlockBytes,
  ]);
}
