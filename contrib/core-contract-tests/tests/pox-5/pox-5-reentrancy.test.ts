import { contractFactory, err } from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { beforeEach, expect, test } from 'vitest';
import { rov, txErr, txOk } from '@clarigen/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { stxToUStx } from '../test-helpers';
import {
  deployer,
  initPox5,
  pox5,
  registerSigner,
  sbtcBalance,
  signSignerKeyGrant,
  testSigner,
} from './pox-5-helpers';

// ERR_REENTRANT_CALL = (err u46) — clarigen types must be regenerated after patch
const ERR_REENTRANT_CALL = 46n;

const alice = accounts.wallet_1.address;

const aliceSbtc = 100000n;
const aliceUstx = stxToUStx(50_000);

beforeEach(() => {
  initPox5();
});

/**
 * A malicious signer whose validate-stake! re-enters pox-5 by calling
 * unstake-sbtc while the reentrancy guard is active. The guard should
 * propagate ERR_REENTRANT_CALL back through try!, causing
 * update-bond-registration to fail entirely with that error code.
 */
test('reentrancy via validate-stake! is blocked with ERR_REENTRANT_CALL', () => {
  const { signer: signer1 } = registerSigner({ caller: deployer });
  const signer1Name = testSigner.identifier.split('.')[1];

  const maliciousName = 'malicious-validate-signer';
  const maliciousId = `${deployer}.${maliciousName}`;

  // validate-stake! re-enters pox-5 by calling unstake-sbtc on Alice's
  // current signer (signer1). The guard is already set, so unstake-sbtc
  // immediately returns ERR_REENTRANT_CALL, which propagates via try!.
  const maliciousSource = `\
(impl-trait .pox-5.signer-manager-trait)
(use-trait signer-manager-trait .pox-5.signer-manager-trait)
(define-public (validate-stake!
    (staker principal) (first-index uint) (num-indexes uint)
    (amount-ustx uint) (amount-sats uint) (is-bond bool)
    (signer-calldata (optional (buff 500))))
  (begin
    (try! (contract-call? .pox-5 unstake-sbtc .${signer1Name} amount-sats))
    (ok true)))
(define-public (checkpoint-staker
    (staker principal) (first-index uint) (num-indexes uint) (is-bond bool))
  (ok true))
(define-public (register-self
    (signer-manager <signer-manager-trait>) (signer-key (buff 33))
    (auth-id uint) (signer-sig (buff 65)))
  (as-contract? ()
    (try! (contract-call? .pox-5 grant-signer-key signer-key current-contract auth-id signer-sig))
    (try! (contract-call? .pox-5 register-signer signer-manager signer-key))))`;

  simnet.deployContract(maliciousName, maliciousSource, { clarityVersion: 4 }, deployer);

  const maliciousSk = secp256k1.utils.randomSecretKey();
  const maliciousKey = secp256k1.getPublicKey(maliciousSk, true);
  const maliciousAuthId = 9001n;
  const maliciousSig = signSignerKeyGrant({
    signerManager: maliciousId,
    authId: maliciousAuthId,
    signerSk: maliciousSk,
  });
  const maliciousContract = contractFactory(project.contracts.testPox5Signer, maliciousId);
  txOk(
    maliciousContract.registerSelf({
      signerKey: maliciousKey,
      signerManager: maliciousId,
      authId: maliciousAuthId,
      signerSig: maliciousSig,
    }),
    deployer,
  );

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: signer1,
      amountUstx: aliceUstx,
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  // Alice pre-authorizes maliciousId so check-caller-allowed passes inside
  // unstake-sbtc, letting execution reach the reentrancy guard.
  txOk(pox5.allowContractCaller(maliciousId, BigInt(simnet.burnBlockHeight + 10)), alice);

  const aliceBalanceLocked = sbtcBalance(alice);

  const result = txErr(
    pox5.updateBondRegistration({
      signerManager: maliciousId,
      signerCalldata: null,
      oldSignerManager: signer1,
    }),
    alice,
  );

  expect(result.value).toBe(ERR_REENTRANT_CALL);
  // sBTC remains locked; Alice's balance is unchanged (not drained).
  expect(sbtcBalance(alice)).toBe(aliceBalanceLocked);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(aliceSbtc);
});

/**
 * A malicious signer whose checkpoint-staker re-enters pox-5. Because
 * update-bond-registration absorbs checkpoint-staker errors with match,
 * the outer call succeeds — but the drain is still blocked by the guard.
 */
test('reentrancy via checkpoint-staker is blocked; update-bond-registration still succeeds', () => {
  const maliciousOldName = 'malicious-checkpoint-signer';
  const maliciousOldId = `${deployer}.${maliciousOldName}`;

  // checkpoint-staker tries to drain Alice's entire sBTC stake. The guard
  // fires before any state change, returning ERR_REENTRANT_CALL. The match
  // in update-bond-registration absorbs the error, so the outer call succeeds.
  const maliciousOldSource = `\
(impl-trait .pox-5.signer-manager-trait)
(use-trait signer-manager-trait .pox-5.signer-manager-trait)
(define-public (validate-stake!
    (staker principal) (first-index uint) (num-indexes uint)
    (amount-ustx uint) (amount-sats uint) (is-bond bool)
    (signer-calldata (optional (buff 500))))
  (ok true))
(define-public (checkpoint-staker
    (staker principal) (first-index uint) (num-indexes uint) (is-bond bool))
  (begin
    (try! (contract-call? .pox-5 stake .test-pox-5-signer u1000000 u1 u0 none))
    (ok true)))
(define-public (register-self
    (signer-manager <signer-manager-trait>) (signer-key (buff 33))
    (auth-id uint) (signer-sig (buff 65)))
  (as-contract? ()
    (try! (contract-call? .pox-5 grant-signer-key signer-key current-contract auth-id signer-sig))
    (try! (contract-call? .pox-5 register-signer signer-manager signer-key))))`;

  simnet.deployContract(maliciousOldName, maliciousOldSource, { clarityVersion: 4 }, deployer);

  const maliciousOldSk = secp256k1.utils.randomSecretKey();
  const maliciousOldKey = secp256k1.getPublicKey(maliciousOldSk, true);
  const maliciousOldAuthId = 9002n;
  const maliciousOldSig = signSignerKeyGrant({
    signerManager: maliciousOldId,
    authId: maliciousOldAuthId,
    signerSk: maliciousOldSk,
  });
  const maliciousOldContract = contractFactory(project.contracts.testPox5Signer, maliciousOldId);
  txOk(
    maliciousOldContract.registerSelf({
      signerKey: maliciousOldKey,
      signerManager: maliciousOldId,
      authId: maliciousOldAuthId,
      signerSig: maliciousOldSig,
    }),
    deployer,
  );

  const { signer: signer2 } = registerSigner({ caller: deployer });

  txOk(
    pox5.setupBond({
      bondIndex: 0n,
      targetRate: 1200n,
      stxValueRatio: 10n,
      minUstxRatio: 100n,
      earlyUnlockSigners: new Uint8Array(),
      earlyUnlockAdmin: deployer,
      allowlist: [{ maxSats: aliceSbtc, staker: alice }],
    }),
    deployer,
  );
  txOk(
    pox5.registerForBond({
      bondIndex: 0n,
      signerManager: maliciousOldId,
      amountUstx: aliceUstx,
      btcLockup: err(aliceSbtc),
      signerCalldata: null,
    }),
    alice,
  );

  const aliceBalanceLocked = sbtcBalance(alice);

  // update-bond-registration succeeds despite the re-entry attempt in checkpoint-staker.
  txOk(
    pox5.updateBondRegistration({
      signerManager: signer2,
      signerCalldata: null,
      oldSignerManager: maliciousOldId,
    }),
    alice,
  );

  // sBTC is still locked; the drain was blocked.
  expect(sbtcBalance(alice)).toBe(aliceBalanceLocked);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(aliceSbtc);

  // Alice is now registered with signer2.
  const membership = rov(pox5.getBondMembership(alice))!;
  expect(membership.signer).toBe(signer2);
});
