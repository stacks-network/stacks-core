import { contractFactory, err } from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { beforeEach, expect, test } from 'vitest';
import { rov, txErr, txOk } from '@clarigen/test';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { stxToUStx } from '../test-helpers';
import {
  deployer,
  errorCodes,
  initPox5,
  pox5,
  registerSigner,
  sbtcBalance,
  signSignerKeyGrant,
  testSigner,
} from './pox-5-helpers';

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
      earlyUnlockBytes: new Uint8Array(),
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

  expect(result.value).toBe(errorCodes.ERR_REENTRANT_CALL);
  // sBTC remains locked; Alice's balance is unchanged (not drained).
  expect(sbtcBalance(alice)).toBe(aliceBalanceLocked);
  expect(rov(pox5.getTotalSbtcStaked())).toBe(aliceSbtc);
});
