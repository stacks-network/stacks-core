import * as BTC from '@scure/btc-signer';
import {
  Cl,
  encodeStructuredDataBytes,
  getAddressFromPublicKey,
  principalCV,
  serializeCV,
  signWithKey,
} from '@stacks/transactions';
import { hex } from '@scure/base';
import {
  extractErrors,
  projectErrors,
  projectFactory,
  contractFactory,
} from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { rov, rovOk, txOk } from '@clarigen/test';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { expect } from 'vitest';
import { randomPoxAddress } from '../test-helpers';

const contracts = projectFactory(project, 'simnet');
// clarinet-sdk applies STX locking only to the boot pox-5 (ST0…AMW42H.pox-5),
// which signer-manager.clar / test-pox-5-signer.clar target. The whole suite's
// `pox5` handle points there. The local [contracts.pox-5] still deploys but is
// unused.
export const POX5_BOOT_ID: string = 'ST000000000000000000002AMW42H.pox-5';
export const pox5 = contractFactory(
  project.contracts.pox5,
  POX5_BOOT_ID,
) as typeof contracts.pox5;
export const errorCodes = projectErrors(project).pox5;
export const testSigner = contracts.testPox5Signer;
export const testSignerErrors = extractErrors(testSigner);
export const signerManager = contracts.signerManager;
export const signerManagerErrors = extractErrors(signerManager);
export const sbtc = contracts.sbtcToken;

export const REWARD_CYCLE_LENGTH = 100n;
export const HALF_CYCLE_LENGTH = REWARD_CYCLE_LENGTH / 2n;
export const BASIS_POINTS = 10000n;
/** Largest value a Clarity `uint` (uint128) can hold. */
export const MAX_UINT128 = 2n ** 128n - 1n;
/** Cap on simultaneously-deployed signer-manager contracts. */
export const MAX_SIGNERS = 10;
/** Cycles between consecutive bond-period starts (contract `BOND_GAP_CYCLES`). */
export const BOND_GAP_CYCLES = 2n;
/** Length of a bond period in cycles (contract `BOND_LENGTH_CYCLES`). */
export const BOND_LENGTH_CYCLES = 12n;

export const deployer = accounts.deployer.address;

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
  stakerUnlockBytes,
  earlyUnlockBytes,
}: {
  stacker: string;
  unlockBurnHeight: bigint;
  stakerUnlockBytes: Uint8Array;
  earlyUnlockBytes: Uint8Array;
}) {
  // `stakerUnlockBytes` and `earlyUnlockBytes` are caller-supplied Bitcoin
  // subscripts (e.g. `<pubkey> OP_CHECKSIG`) that the contract splices
  // in raw — they must NOT go through `Script.encode` as Uint8Array
  // elements, which would wrap them in an OP_PUSHBYTES_N push.
  //
  // The staker principal is committed as a hashed value and checked in the
  // OP_ELSE branch, so the shape is:
  //   OP_IF <unlock-burn-height> OP_CHECKLOCKTIMEVERIFY
  //   OP_ELSE OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY
  //           <earlyUnlockBytes>
  //   OP_ENDIF OP_VERIFY <stakerUnlockBytes>
  const stackerEncoded = serializeCV(principalCV(stacker));
  const principalHash = sha256(sha256(hex.decode(stackerEncoded)));
  const ifElsePrefix = BTC.Script.encode([
    'IF',
    Number(unlockBurnHeight),
    'CHECKLOCKTIMEVERIFY',
    'ELSE',
    'SIZE',
    32,
    'EQUALVERIFY',
    'SHA256',
    principalHash,
    'EQUALVERIFY',
  ]);
  const endifVerify = BTC.Script.encode(['ENDIF', 'VERIFY']);
  return concatBytes(
    ifElsePrefix,
    earlyUnlockBytes,
    endifVerify,
    stakerUnlockBytes,
  );
}

/**
 * Build a fake-but-parseable L1 lockup output for a register-for-bond call.
 * The code requires real Bitcoin tx bytes, and the merkle-proof check is
 * satisfied via the single-tx shortcut (block merkle-root equals the
 * canonical txid).
 */
export function buildL1Lockup({
  staker,
  sats,
  bondIndex,
  stakerUnlockBytes = new Uint8Array(),
  earlyUnlockBytes = new Uint8Array(),
}: {
  staker: string;
  sats: bigint;
  bondIndex: bigint;
  stakerUnlockBytes?: Uint8Array;
  earlyUnlockBytes?: Uint8Array;
}) {
  const unlockBurnHeight = rov(pox5.getBondL1UnlockHeight(bondIndex));
  const lockupScript = serializeLockupScript({
    stacker: staker,
    unlockBurnHeight,
    stakerUnlockBytes,
    earlyUnlockBytes,
  });
  const outputScript = toWitnessOutput(lockupScript);

  const txBytes = BTC.RawTx.encode({
    version: 1,
    segwitFlag: false,
    inputs: [
      {
        txid: new Uint8Array(32),
        index: 0xffffffff,
        finalScriptSig: new Uint8Array(),
        sequence: 0xffffffff,
      },
    ],
    outputs: [{ amount: sats, script: outputScript }],
    witnesses: undefined,
    lockTime: 0,
  });

  // Canonical (non-segwit) txid = double-sha256 of the serialized tx, in
  // internal byte order. Place it as the merkle-root field (bytes 36..68)
  // so the contract's single-tx shortcut matches.
  const txid = sha256(sha256(txBytes));
  const header = new Uint8Array(80);
  header.set(txid, 36);

  return {
    amount: sats,
    outputIndex: 0n,
    header,
    leafHashes: [] as Uint8Array[],
    txCount: 1n,
    txIndex: 0n,
    height: 0n,
    tx: txBytes,
  };
}

export function sbtcBalance(address: string): bigint {
  return rovOk(sbtc.getBalance(address));
}

/** Helper that returns the start height of the next reward cycle */
export function getStartHeight() {
  const nextCycle = rov(pox5.currentPoxRewardCycle()) + 1n;
  return rov(pox5.rewardCycleToBurnHeight(nextCycle));
}

export function signSignerKeyGrant({
  signerManager,
  authId,
  signerSk,
}: {
  signerManager: string;
  authId: bigint;
  signerSk: Uint8Array;
}) {
  const message = Cl.tuple({
    'signer-manager': Cl.principal(signerManager),
    topic: Cl.stringAscii('grant-authorization'),
    'auth-id': Cl.uint(authId),
  });
  const fullMessage = encodeStructuredDataBytes({
    message,
    domain: Cl.tuple({
      name: Cl.stringAscii(pox5.constants.pOX_5_SIGNER_DOMAIN.name),
      version: Cl.stringAscii(pox5.constants.pOX_5_SIGNER_DOMAIN.version),
      'chain-id': Cl.uint(pox5.constants.pOX_5_SIGNER_DOMAIN.chainId),
    }),
  });
  const data = signWithKey(signerSk, hex.encode(sha256(fullMessage)));
  const signature = hex.decode(data.slice(2) + data.slice(0, 2));
  return signature;
}

export function createSignerKeyGrant({
  signerManager: staker,
  signerSk,
  authId,
}: {
  signerManager: string;
  signerSk: Uint8Array;
  authId: bigint;
}) {
  const signature = signSignerKeyGrant({
    signerManager: staker,
    authId,
    signerSk,
  });
  txOk(
    pox5.grantSignerKey({
      signerKey: secp256k1.getPublicKey(signerSk, true),
      signerSig: signature,
      signerManager: staker,
      authId,
    }),
    accounts.deployer.address,
  );
}

let grantAuthIdCounter = 1000n;

/** Create a signer key grant for `staker` (any pox-addr) and return the key pair. */
export function setupSigner(signerManager: string) {
  const signerSk = secp256k1.utils.randomSecretKey();
  const signerKey = secp256k1.getPublicKey(signerSk, true);
  const authId = grantAuthIdCounter++;
  createSignerKeyGrant({
    signerManager,
    signerSk,
    authId,
  });
  return { signerSk, signerKey };
}

/** Get the testnet STX address for a signer key. */
export function signerAddress(signerKey: Uint8Array) {
  return getAddressFromPublicKey(signerKey, 'testnet');
}

/** Sign a per-transaction signer authorization (the signer-sig path). */
export function signPerTransactionAuth({
  signerSk,
  poxAddr,
  rewardCycle,
  topic,
  period,
  maxAmount,
  authId,
}: {
  signerSk: Uint8Array;
  poxAddr: { version: Uint8Array; hashbytes: Uint8Array };
  rewardCycle: bigint;
  topic: string;
  period: bigint | number;
  maxAmount: bigint | number;
  authId: bigint | number;
}) {
  const message = Cl.tuple({
    'pox-addr': Cl.tuple({
      version: Cl.buffer(poxAddr.version),
      hashbytes: Cl.buffer(poxAddr.hashbytes),
    }),
    'reward-cycle': Cl.uint(rewardCycle),
    topic: Cl.stringAscii(topic),
    period: Cl.uint(period),
    'auth-id': Cl.uint(authId),
    'max-amount': Cl.uint(maxAmount),
  });
  const fullMessage = encodeStructuredDataBytes({
    message,
    domain: Cl.tuple({
      name: Cl.stringAscii(pox5.constants.pOX_5_SIGNER_DOMAIN.name),
      version: Cl.stringAscii(pox5.constants.pOX_5_SIGNER_DOMAIN.version),
      'chain-id': Cl.uint(pox5.constants.pOX_5_SIGNER_DOMAIN.chainId),
    }),
  });
  const data = signWithKey(signerSk, hex.encode(sha256(fullMessage)));
  return hex.decode(data.slice(2) + data.slice(0, 2));
}

/**
 * Register a test-pox-5-signer instance with a valid signer key grant.
 *
 * Defaults to the project's `testSigner`; pass `signerManager` to register a
 * different deployed instance (e.g. one returned by `deployTestSignerContract`).
 * Passing both `seed` and `authId` makes the call fully deterministic;
 * omitting them uses fresh entropy and the module-level auth-id counter.
 */
export function registerSigner({
  signerManager = testSigner,
  caller = deployer,
  seed,
  authId,
}: {
  signerManager?: typeof testSigner;
  caller?: string;
  seed?: Uint8Array;
  authId?: bigint;
} = {}) {
  const signerSk = secp256k1.utils.randomSecretKey(seed);
  const signerKey = secp256k1.getPublicKey(signerSk, true);
  const resolvedAuthId = authId ?? grantAuthIdCounter++;
  const signature = signSignerKeyGrant({
    signerManager: signerManager.identifier,
    authId: resolvedAuthId,
    signerSk,
  });
  txOk(
    signerManager.registerSelf({
      signerKey,
      signerManager: signerManager.identifier,
      authId: resolvedAuthId,
      signerSig: signature,
    }),
    caller,
  );
  return { signerKey, signer: signerManager.identifier };
}

/**
 * Deploy a fresh test-pox-5-signer contract instance (using the same source
 * as the default `testSigner`) but do NOT register it. Returns a typed
 * contract handle that can be passed to `registerSigner({ signerManager })`.
 */
export function deployTestSignerContract(name: string) {
  const newId = `${accounts.deployer.address}.${name}`;
  const signerSource = simnet.getContractSource(testSigner.identifier)!;
  simnet.deployContract(
    name,
    signerSource,
    // @ts-ignore
    { clarityVersion: 6 },
    accounts.deployer.address,
  );
  return testSignerHandle(newId);
}

/**
 * Reconstruct a typed test-pox-5-signer contract handle for an identifier
 * that was already deployed earlier in the session (e.g. tracked in the
 * stateful test model).
 */
export function testSignerHandle(identifier: string): typeof testSigner {
  return contractFactory(
    project.contracts.testPox5Signer,
    identifier,
  ) as typeof testSigner;
}

export function registerSignerManager() {
  const signerSk = secp256k1.utils.randomSecretKey();
  const signature = signSignerKeyGrant({
    signerManager: signerManager.identifier,
    authId: 1n,
    signerSk,
  });
  txOk(
    signerManager.registerSelf({
      signerKey: secp256k1.getPublicKey(signerSk, true),
      signerManager: signerManager.identifier,
      authId: 1n,
      signerSig: signature,
    }),
    deployer,
  );
}

/**
 * Deploy and setup a new signer
 */
export function deployTestSigner(name: string) {
  const testSigner2Id = `${accounts.deployer.address}.${name}`;
  const signerSource = simnet.getContractSource(testSigner.identifier)!;
  const testSigner2 = contractFactory(
    project.contracts.testPox5Signer,
    testSigner2Id,
  );
  const signerSk = secp256k1.utils.randomSecretKey();
  const signerKey = secp256k1.getPublicKey(signerSk, true);
  const authId = grantAuthIdCounter++;
  const signature = signSignerKeyGrant({
    signerManager: testSigner2.identifier,
    authId,
    signerSk,
  });
  simnet.deployContract(
    name,
    signerSource,
    {
      clarityVersion: 4,
    },
    accounts.deployer.address,
  );
  txOk(
    testSigner2.registerSelf({
      signerKey: signerKey,
      signerManager: testSigner2.identifier,
      authId,
      signerSig: signature,
    }),
    accounts.deployer.address,
  );

  return testSigner2;
}

export function isSignerInCycle({
  signer,
  cycle,
}: {
  signer: string;
  cycle: bigint;
}): boolean {
  return rov(pox5.getSignerSetItemForCycle({ cycle, signer })) !== null;
}

/** Get all stakers for the next reward cycle */
export function getAllStakers(): string[] {
  const nextCycle = rov(pox5.currentPoxRewardCycle()) + 1n;
  return getAllStakersForCycle(nextCycle);
}

/** Get all stakers for a given reward cycle */
function getAllStakersForCycle(cycle: bigint): string[] {
  const first = rov(pox5.getSignerSetFirstItemForCycle(cycle));
  let signers: string[] = [];
  let cur: string | null = first;
  if (cur) signers.push(cur);
  while (cur) {
    const item = rov(pox5.getSignerSetNextItemForCycle(cur, cycle));
    if (item) signers.push(item);
    cur = item;
  }
  return signers;
}

export function expectAllSignersHaveKeys() {
  const stakers = getAllStakers();
  for (const staker of stakers) {
    const signerKey = rov(pox5.getSignerInfo(staker));
    expect(signerKey).not.toBeNull();
  }
}

export function initPox5() {
  // With `override_boot_contracts_source`, the boot pox-5 is our raw
  // pox-5.clar, so its initial bond-admin is the mainnet placeholder it ships
  // with.
  const INITIAL_BOND_ADMIN = 'SP000000000000000000002Q6VF78';

  txOk(
    pox5.setBurnchainParameters({
      firstBurnHeight: 0n,
      prepareCycleLength: 10n,
      rewardCycleLength: REWARD_CYCLE_LENGTH,
      beginPox5RewardCycle: 1n,
    }),
    deployer,
  );
  txOk(pox5.setBondAdmin(deployer), INITIAL_BOND_ADMIN);
}

//  The boot-deployed pox-5 (`ST0…AMW42H.pox-5`) that clarinet-sdk recognizes
//  and applies STX locking to. `signer-manager.clar` now targets this instance,
//  so the test infra must register/stake against it. The local
//  `[contracts.pox-5]` is not lock-aware in simnet. Typed via the local ABI
//  re-pointed at the boot id.

/** `initPox5` for the boot instance: burnchain params only (no bond-admin). */
export function initBootPox5() {
  txOk(
    pox5.setBurnchainParameters({
      firstBurnHeight: 0n,
      prepareCycleLength: 10n,
      rewardCycleLength: REWARD_CYCLE_LENGTH,
      beginPox5RewardCycle: 1n,
    }),
    deployer,
  );
  // Hand bond-admin from the shipped mainnet placeholder to the deployer so
  // the stateful test can drive `setup-bond`.
  txOk(pox5.setBondAdmin(deployer), 'SP000000000000000000002Q6VF78');
}

export function sbtcTransfer(
  amount: bigint,
  sender: string,
  recipient: string,
) {
  txOk(
    sbtc.transfer({
      recipient,
      amount,
      sender,
      memo: null,
    }),
    sender,
  );
}

export function makePoxAddrCalldata(
  { maxFee }: { maxFee: bigint } = { maxFee: 100n },
) {
  const poxAddr = randomPoxAddress();
  return {
    poxAddr,
    maxFee,
    calldata: hex.decode(
      serializeCV(
        Cl.tuple({
          'pox-addr': Cl.tuple({
            version: Cl.buffer(poxAddr.version),
            hashbytes: Cl.buffer(poxAddr.hashbytes),
          }),
          'max-fee': Cl.uint(maxFee),
        }),
      ),
    ),
  };
}
