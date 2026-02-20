import * as BTC from '@scure/btc-signer';
import { createAddress } from '@stacks/transactions';
import { hex } from '@scure/base';
import { projectErrors, projectFactory } from '@clarigen/core';
import { project } from '../clarigen-types';
import { rov } from '@clarigen/test';

const contracts = projectFactory(project, 'simnet');
export const pox5 = contracts.pox5;
export const errorCodes = projectErrors(project).pox5;

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

/** Helper that returns the start height of the next reward cycle */
export function getStartHeight() {
  const nextCycle = rov(pox5.currentPoxRewardCycle()) + 1n;
  return rov(pox5.rewardCycleToBurnHeight(nextCycle));
}
