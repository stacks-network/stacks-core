import { rov, txErr, txOk } from '@clarigen/test';
import { beforeEach, expect, test } from 'vitest';
import { accounts } from '../clarigen-types';
import { randomPoxAddress, stxToUStx } from '../test-helpers';
import {
  initPox5,
  payoutConfigCalldata,
  pox5,
  randomPayoutConfig,
  registerSignerManagerCore,
  signerManagerCore,
  signerManagerCoreErrors,
  signerManagerV1,
  signerManagerV1Errors,
  testSignerManagerV2,
} from './pox-5-helpers';

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;

beforeEach(() => {
  initPox5();
  registerSignerManagerCore();
});

function stake(signerCalldata: Uint8Array | null = null) {
  return pox5.stake({
    signerManager: signerManagerCore.identifier,
    amountUstx: stxToUStx(50_000),
    numCycles: 2n,
    startBurnHt: simnet.burnBlockHeight,
    signerCalldata,
  });
}

test('core is registered with pox-5 and controlled by the v1 module', () => {
  expect(rov(pox5.getSignerInfo(signerManagerCore.identifier))).not.toBeNull();
  expect(rov(signerManagerCore.getCurrentModule())).toBe(
    signerManagerV1.identifier,
  );
});

test('staking with payout-config calldata stores the config', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 5000n });
  txOk(stake(payoutConfigCalldata(config)), alice);
  expect(rov(signerManagerCore.getPayoutConfig(alice))).toEqual(config);
  // The module exposes the same view.
  expect(rov(signerManagerV1.getPayoutConfig(alice))).toEqual(config);
});

test('staking without calldata leaves an existing config untouched', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  txOk(stake(payoutConfigCalldata(config)), alice);
  txOk(
    pox5.stakeUpdate({
      signerManager: signerManagerCore.identifier,
      oldSignerManager: signerManagerCore.identifier,
      cyclesToExtend: 1n,
      amountIncrease: 0n,
      signerCalldata: null,
    }),
    alice,
  );
  expect(rov(signerManagerCore.getPayoutConfig(alice))).toEqual(config);
  txOk(stake(), bob);
  expect(rov(signerManagerCore.getPayoutConfig(bob))).toBeNull();
});

test('malformed calldata and pox-addrs are rejected', () => {
  expect(txErr(stake(new Uint8Array([1, 2, 3])), alice).value).toBe(
    signerManagerCoreErrors.ERR_INVALID_CALLDATA,
  );
  // Version 0x06 is above the highest sBTC address version.
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  config.l1Withdrawal!.poxAddr.version = new Uint8Array([0x06]);
  expect(txErr(stake(payoutConfigCalldata(config)), alice).value).toBe(
    signerManagerCoreErrors.ERR_INVALID_POX_ADDR,
  );
  expect(
    txErr(
      signerManagerV1.setPayoutConfig({
        l1Withdrawal: config.l1Withdrawal,
        sbtcRecipient: null,
      }),
      alice,
    ).value,
  ).toBe(signerManagerCoreErrors.ERR_INVALID_POX_ADDR);
  expect(rov(signerManagerCore.getPayoutConfig(alice))).toBeNull();
});

test('validate-stake! errors when not called by the pox-5 contract', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  expect(
    txErr(
      signerManagerCore.validateStake_x({
        staker: alice,
        firstIndex: 0n,
        numIndexes: 1n,
        amountUstx: stxToUStx(50_000),
        amountSats: 0n,
        isBond: false,
        signerCalldata: payoutConfigCalldata(config),
      }),
      alice,
    ).value,
  ).toBe(signerManagerCoreErrors.ERR_UNAUTHORIZED_CALLER);
  expect(rov(signerManagerCore.getPayoutConfig(alice))).toBeNull();
});

test('stakers set and clear their payout config through the module', () => {
  txOk(stake(), alice);
  const l1Withdrawal = {
    poxAddr: randomPoxAddress(),
    maxFee: 200n,
    minClaim: 1000n,
  };
  txOk(
    signerManagerV1.setPayoutConfig({ l1Withdrawal, sbtcRecipient: null }),
    alice,
  );
  expect(rov(signerManagerCore.getPayoutConfig(alice))).toEqual({
    l1Withdrawal,
    sbtcRecipient: null,
  });
  // Switch to sBTC paid to another address.
  txOk(
    signerManagerV1.setPayoutConfig({ l1Withdrawal: null, sbtcRecipient: bob }),
    alice,
  );
  expect(rov(signerManagerCore.getPayoutConfig(alice))).toEqual({
    l1Withdrawal: null,
    sbtcRecipient: bob,
  });
  txOk(signerManagerV1.clearPayoutConfig(), alice);
  expect(rov(signerManagerCore.getPayoutConfig(alice))).toBeNull();
});

test('core functions reject callers other than the module', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  expect(
    txErr(signerManagerCore.setPayoutConfig({ staker: alice, config }), alice)
      .value,
  ).toBe(signerManagerCoreErrors.ERR_UNAUTHORIZED_MODULE);
  expect(
    txErr(signerManagerCore.clearPayoutConfig(alice), deployer).value,
  ).toBe(signerManagerCoreErrors.ERR_UNAUTHORIZED_MODULE);
  // The deployer was only the bootstrap module; it lost control at hand-off.
  expect(txErr(signerManagerCore.setModule(alice), deployer).value).toBe(
    signerManagerCoreErrors.ERR_UNAUTHORIZED_MODULE,
  );
});

test('admins upgrade by pointing core at a new module', () => {
  expect(
    txErr(signerManagerV1.setModule(testSignerManagerV2.identifier), alice)
      .value,
  ).toBe(signerManagerV1Errors.ERR_UNAUTHORIZED_ADMIN);
  // A principal with no contract behind it would strand core forever.
  expect(txErr(signerManagerV1.setModule(alice), deployer).value).toBe(
    signerManagerCoreErrors.ERR_INVALID_MODULE,
  );
  txOk(signerManagerV1.setModule(testSignerManagerV2.identifier), deployer);
  expect(rov(signerManagerCore.getCurrentModule())).toBe(
    testSignerManagerV2.identifier,
  );
  // The old module is cut off.
  expect(
    txErr(
      signerManagerV1.setPayoutConfig({
        l1Withdrawal: null,
        sbtcRecipient: null,
      }),
      bob,
    ).value,
  ).toBe(signerManagerCoreErrors.ERR_UNAUTHORIZED_MODULE);
});

test('only admins can update admins', () => {
  expect(
    txErr(signerManagerV1.updateAdmin({ admin: alice, enabled: true }), alice)
      .value,
  ).toBe(signerManagerV1Errors.ERR_UNAUTHORIZED_ADMIN);
  txOk(signerManagerV1.updateAdmin({ admin: alice, enabled: true }), deployer);
  expect(rov(signerManagerV1.isAdmin(alice))).toBe(true);
  txOk(signerManagerV1.setModule(testSignerManagerV2.identifier), alice);
});
