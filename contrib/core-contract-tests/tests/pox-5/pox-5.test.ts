import { project, accounts } from '../clarigen-types'; // where your [types.output] was specified
import { projectErrors, projectFactory } from '@clarigen/core';
import { rov, txErr, txOk } from '@clarigen/test';
import { test, expect, describe } from 'vitest';
import { randomStacksAddress } from '../test-helpers';
import { hex } from '@scure/base';
import * as BTC from '@scure/btc-signer';
import { serializeLockupScript } from './pox-5-helpers';

const contracts = projectFactory(project, 'simnet');
const contract = contracts.pox5;
const errorCodes = projectErrors(project).pox5;

function getAllStackers() {
  const first = rov(contract.getStackerSetFirstItem());
  let stackers: string[] = [];
  let cur: string | null = first;
  if (cur) stackers.push(cur);
  while (cur) {
    const item = rov(contract.getStackerSetNextItem(cur));
    if (item) stackers.push(item);
    cur = item;
  }
  return stackers;
}

describe('linked list', () => {
  const stackers = [
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
    randomStacksAddress(),
  ];
  test('can add multiple stackers to the linked list', () => {
    for (const stacker of stackers) {
      txOk(contract.addStackerToSet(stacker), accounts.deployer.address);
    }
    const lastItem = rov(contract.getStackerSetLastItem());
    expect(lastItem).toBe(stackers.at(-1));
    expect(rov(contract.getStackerSetFirstItem())).toBe(stackers[0]);
    const allStackers = getAllStackers();
    expect(allStackers).toEqual(stackers);
  });

  test('can remove a non-last item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(contract.addStackerToSet(stacker), accounts.deployer.address);
    }
    const toRemove = stackers[1]!;
    txOk(contract.removeStackerFromSet(toRemove), accounts.deployer.address);
    const allStackers = getAllStackers();
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(contract.getStackerSetNextItem(stackers[0]!))).toBe(
      stackers[2]!,
    );
    expect(rov(contract.getStackerSetPrevItem(stackers[2]!))).not.toBe(
      toRemove,
    );
    expect(rov(contract.getStackerSetPrevItem(stackers[2]!))).toBe(
      stackers[0]!,
    );
    expect(rov(contract.getStackerSetPrevItem(toRemove))).toBe(null);
    expect(rov(contract.getStackerSetNextItem(toRemove))).toBe(null);
  });

  test('can remove the last item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(contract.addStackerToSet(stacker), accounts.deployer.address);
    }
    const toRemove = stackers.at(-1)!;
    const newLast = stackers.at(-2)!;
    txOk(contract.removeStackerFromSet(toRemove), accounts.deployer.address);
    const allStackers = getAllStackers();
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(contract.getStackerSetLastItem())).toBe(newLast);
    expect(rov(contract.getStackerSetFirstItem())).toBe(stackers[0]!);
    expect(rov(contract.getStackerSetNextItem(newLast))).toBe(null);
    expect(rov(contract.getStackerSetPrevItem(newLast))).toBe(stackers.at(-3));
    expect(rov(contract.getStackerSetPrevItem(toRemove))).toBe(null);
    expect(rov(contract.getStackerSetNextItem(toRemove))).toBe(null);
  });

  test('can remove the first item from the linked list', () => {
    for (const stacker of stackers) {
      txOk(contract.addStackerToSet(stacker), accounts.deployer.address);
    }
    const toRemove = stackers[0]!;
    const newFirst = stackers[1]!;
    txOk(contract.removeStackerFromSet(toRemove), accounts.deployer.address);
    const allStackers = getAllStackers();
    expect(allStackers).toEqual(stackers.filter((s) => s !== toRemove));
    expect(rov(contract.getStackerSetFirstItem())).toBe(newFirst);
    expect(rov(contract.getStackerSetLastItem())).toBe(stackers.at(-1)!);
    expect(rov(contract.getStackerSetNextItem(newFirst))).toBe(stackers[2]!);
    expect(rov(contract.getStackerSetPrevItem(newFirst))).toBe(null);
    expect(rov(contract.getStackerSetPrevItem(toRemove))).toBe(null);
    expect(rov(contract.getStackerSetNextItem(toRemove))).toBe(null);
  });

  test('cannot add a stacker that is already in the linked list', () => {
    txOk(contract.addStackerToSet(stackers[0]!), accounts.deployer.address);
    const result = txErr(
      contract.addStackerToSet(stackers[0]!),
      accounts.deployer.address,
    );
    expect(result.value).toEqual(errorCodes.ERR_STACKING_ALREADY_STACKED);
  });

  test('cannot remove a stacker that is not in the linked list', () => {
    const result = txErr(
      contract.removeStackerFromSet(stackers[0]!),
      accounts.deployer.address,
    );
    expect(result.value).toEqual(errorCodes.ERR_NOT_STACKED);
  });
});

describe('constructing lockup scripts', () => {
  test('can get the byte for a u8', () => {
    const n = 123;
    const expected = BTC.ScriptNum().encode(BigInt(n));
    const buff = rov(contract.uintToBuffLe(n));
    expect(hex.encode(buff)).toStrictEqual(hex.encode(expected));
  });

  test('can construct a lockup script', () => {
    const stacker = 'STAPZXVFZRPKHRK4MAVR9WV1EZAZA157K6E20SBW';
    const unlockBurnHeight = 1_000_000n;
    const unlockBytes = hex.decode(
      '76a914de9db0e31c16b05c0b2d5be612fb3c5a6c41a25188ac',
    );
    const lockupScriptJs = serializeLockupScript({
      stacker,
      unlockBurnHeight,
      unlockBytes,
    });
    const lockupScript = rov(
      contract.constructUnlockScript({
        stacker,
        unlockBurnHeight: BTC.ScriptNum().encode(unlockBurnHeight),
        unlockBytes,
      }),
    );
    expect(hex.encode(lockupScript)).toStrictEqual(hex.encode(lockupScriptJs));
  });
});
