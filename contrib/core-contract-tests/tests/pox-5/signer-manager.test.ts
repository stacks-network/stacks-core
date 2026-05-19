import { beforeEach, expect, test } from 'vitest';
import {
  signerManager,
  signerManagerErrors,
  pox5,
  initPox5,
  registerSignerManager,
} from './pox-5-helpers';
import { rov, txOk } from '@clarigen/test';
import { hex } from '@scure/base';
import { accounts } from '../clarigen-types';
import { randomPoxAddress } from '../test-helpers';
import { Cl, serializeCV } from '@stacks/transactions';

const REWARD_CYCLE_LENGTH = 100n;
const HALF_CYCLE_LENGTH = REWARD_CYCLE_LENGTH / 2n;
const BASIS_POINTS = 10000n;

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;
const charlie = accounts.wallet_3.address;
const dave = accounts.wallet_4.address;
const emily = accounts.wallet_5.address;

beforeEach(() => {
  initPox5();
  registerSignerManager();
});

function makePoxAddrCalldata() {
  const poxAddr = randomPoxAddress();
  return {
    poxAddr,
    calldata: hex.decode(
      serializeCV(
        Cl.tuple({
          version: Cl.buffer(poxAddr.version),
          hashbytes: Cl.buffer(poxAddr.hashbytes),
        }),
      ),
    ),
  };
}

test('signers have pox-addr saved from calldata when provided', () => {
  const { poxAddr, calldata } = makePoxAddrCalldata();
  txOk(
    pox5.stake({
      signerManager: signerManager.identifier,
      amountUstx: 100000000n,
      numCycles: 1n,
      startBurnHt: simnet.burnBlockHeight,
      signerCalldata: calldata,
    }),
    alice,
  );
  expect(rov(signerManager.getPoxAddr(alice))).toEqual(poxAddr);
});
