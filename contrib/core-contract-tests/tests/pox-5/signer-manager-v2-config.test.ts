import { rov, rovErr, rovOk, txErr, txOk } from '@clarigen/test';
import { beforeEach, expect, test } from 'vitest';
import { accounts } from '../clarigen-types';
import { randomPoxAddress, stxToUStx } from '../test-helpers';
import {
  initPox5,
  payoutConfigCalldata,
  pox5,
  randomPayoutConfig,
  registerSignerManagerV2,
  signerManagerV2,
  signerManagerV2Errors,
} from './pox-5-helpers';

const deployer = accounts.deployer.address;
const alice = accounts.wallet_1.address;
const bob = accounts.wallet_2.address;
const charlie = accounts.wallet_3.address;

beforeEach(() => {
  initPox5();
  registerSignerManagerV2();
});

function stake(signerCalldata: Uint8Array | null = null) {
  return pox5.stake({
    signerManager: signerManagerV2.identifier,
    amountUstx: stxToUStx(50_000),
    numCycles: 2n,
    startBurnHt: simnet.burnBlockHeight,
    signerCalldata,
  });
}

test('v2 is registered directly with pox-5', () => {
  expect(rov(pox5.getSignerInfo(signerManagerV2.identifier))).not.toBeNull();
});

test('staking with payout-config calldata stores the config', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 5000n });
  txOk(stake(payoutConfigCalldata(config)), alice);
  expect(rov(signerManagerV2.getPayoutConfig(alice))).toEqual(config);
});

test('staking without calldata clears an existing config', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  txOk(stake(payoutConfigCalldata(config)), alice);
  txOk(
    pox5.stakeUpdate({
      signerManager: signerManagerV2.identifier,
      oldSignerManager: signerManagerV2.identifier,
      cyclesToExtend: 1n,
      amountIncrease: 0n,
      signerCalldata: null,
    }),
    alice,
  );
  expect(rov(signerManagerV2.getPayoutConfig(alice))).toBeNull();
  txOk(stake(), bob);
  expect(rov(signerManagerV2.getPayoutConfig(bob))).toBeNull();
});

test('malformed calldata and pox-addrs are rejected', () => {
  expect(txErr(stake(new Uint8Array([1, 2, 3])), alice).value).toBe(
    signerManagerV2Errors.ERR_INVALID_CALLDATA,
  );
  // Version 0x06 is above the highest sBTC address version.
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  expect(
    rovOk(signerManagerV2.checkPoxAddr(config.l1Withdrawal!.poxAddr)),
  ).toBe(true);
  config.l1Withdrawal!.poxAddr.version = new Uint8Array([0x06]);
  expect(
    rovErr(signerManagerV2.checkPoxAddr(config.l1Withdrawal!.poxAddr)),
  ).toBe(signerManagerV2Errors.ERR_INVALID_POX_ADDR);
  expect(txErr(stake(payoutConfigCalldata(config)), alice).value).toBe(
    signerManagerV2Errors.ERR_INVALID_POX_ADDR,
  );
  expect(
    txErr(
      signerManagerV2.setPayoutConfig({
        l1Withdrawal: config.l1Withdrawal,
        sbtcRecipient: null,
      }),
      alice,
    ).value,
  ).toBe(signerManagerV2Errors.ERR_INVALID_POX_ADDR);
  expect(rov(signerManagerV2.getPayoutConfig(alice))).toBeNull();
});

test('validate-stake! errors when not called by the pox-5 contract', () => {
  const config = randomPayoutConfig({ maxFee: 100n, minClaim: 0n });
  expect(
    txErr(
      signerManagerV2.validateStake_x({
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
  ).toBe(signerManagerV2Errors.ERR_UNAUTHORIZED_CALLER);
  expect(rov(signerManagerV2.getPayoutConfig(alice))).toBeNull();
});

test('stakers set and clear their payout config directly', () => {
  txOk(stake(), alice);
  const l1Withdrawal = {
    poxAddr: randomPoxAddress(),
    maxFee: 200n,
    minClaim: 1000n,
  };
  txOk(
    signerManagerV2.setPayoutConfig({ l1Withdrawal, sbtcRecipient: null }),
    alice,
  );
  expect(rov(signerManagerV2.getPayoutConfig(alice))).toEqual({
    l1Withdrawal,
    sbtcRecipient: null,
  });
  // Switch to sBTC paid to another address.
  txOk(
    signerManagerV2.setPayoutConfig({ l1Withdrawal: null, sbtcRecipient: bob }),
    alice,
  );
  expect(rov(signerManagerV2.getPayoutConfig(alice))).toEqual({
    l1Withdrawal: null,
    sbtcRecipient: bob,
  });
  txOk(signerManagerV2.clearPayoutConfig(), alice);
  expect(rov(signerManagerV2.getPayoutConfig(alice))).toBeNull();
});

test('the allowlist is off by default and gates staking once enabled', () => {
  expect(rov(signerManagerV2.getUseAllowlist())).toBe(false);
  txOk(stake(), alice);

  expect(txErr(signerManagerV2.setUseAllowlist(true), alice).value).toBe(
    signerManagerV2Errors.ERR_UNAUTHORIZED_ADMIN,
  );
  expect(
    txErr(signerManagerV2.setAllowlisted({ staker: bob, allowed: true }), alice)
      .value,
  ).toBe(signerManagerV2Errors.ERR_UNAUTHORIZED_ADMIN);

  txOk(signerManagerV2.setUseAllowlist(true), deployer);
  expect(txErr(stake(), bob).value).toBe(
    signerManagerV2Errors.ERR_NOT_ALLOWLISTED,
  );
  // Existing positions are checked again on their next pox-5 call.
  expect(
    txErr(
      pox5.stakeUpdate({
        signerManager: signerManagerV2.identifier,
        oldSignerManager: signerManagerV2.identifier,
        cyclesToExtend: 1n,
        amountIncrease: 0n,
        signerCalldata: null,
      }),
      alice,
    ).value,
  ).toBe(signerManagerV2Errors.ERR_NOT_ALLOWLISTED);

  txOk(
    signerManagerV2.setAllowlisted({ staker: bob, allowed: true }),
    deployer,
  );
  expect(rov(signerManagerV2.isAllowlisted(bob))).toBe(true);
  txOk(stake(), bob);

  txOk(
    signerManagerV2.setAllowlisted({ staker: bob, allowed: false }),
    deployer,
  );
  expect(rov(signerManagerV2.isAllowlisted(bob))).toBe(false);
  txOk(signerManagerV2.setUseAllowlist(false), deployer);
  txOk(stake(), charlie);
});

test('admins set and clear the signer metadata uri', () => {
  const uri = 'https://example.com/signer.json';
  expect(rovOk(signerManagerV2.getTokenUri())).toBeNull();

  expect(txErr(signerManagerV2.setTokenUri(uri), alice).value).toBe(
    signerManagerV2Errors.ERR_UNAUTHORIZED_ADMIN,
  );

  txOk(signerManagerV2.setTokenUri(uri), deployer);
  expect(rovOk(signerManagerV2.getTokenUri())).toBe(uri);

  txOk(signerManagerV2.setTokenUri(null), deployer);
  expect(rovOk(signerManagerV2.getTokenUri())).toBeNull();
});
