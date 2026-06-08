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
export const pox5 = contracts.pox5;
export const errorCodes = projectErrors(project).pox5;
export const testSigner = contracts.testPox5Signer;
export const testSignerErrors = extractErrors(testSigner);
export const signerManager = contracts.signerManager;
export const signerManagerErrors = extractErrors(signerManager);
export const sbtc = contracts.sbtcToken;

export const REWARD_CYCLE_LENGTH = 100n;
export const HALF_CYCLE_LENGTH = REWARD_CYCLE_LENGTH / 2n;
export const BASIS_POINTS = 10000n;

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
  unlockBytes,
  earlyUnlockBytes,
}: {
  stacker: string;
  unlockBurnHeight: bigint;
  unlockBytes: Uint8Array;
  earlyUnlockBytes: Uint8Array;
}) {
  // `unlockBytes` and `earlyUnlockBytes` are caller-supplied Bitcoin
  // subscripts (e.g. `<pubkey> OP_CHECKSIG`) that the contract splices
  // in raw — they must NOT go through `Script.encode` as Uint8Array
  // elements, which would wrap them in an OP_PUSHBYTES_N push.
  const stackerEncoded = serializeCV(principalCV(stacker));
  const prefix = BTC.Script.encode([
    hex.decode(stackerEncoded),
    'DROP',
    'IF',
    Number(unlockBurnHeight),
    'CHECKLOCKTIMEVERIFY',
    'DROP',
  ]);
  const OP_ELSE = new Uint8Array([0x67]);
  const OP_ENDIF = new Uint8Array([0x68]);
  return concatBytes(
    prefix,
    unlockBytes,
    OP_ELSE,
    earlyUnlockBytes,
    unlockBytes,
    OP_ENDIF,
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
  unlockBytes = new Uint8Array(),
  earlyUnlockBytes = new Uint8Array(),
}: {
  staker: string;
  sats: bigint;
  bondIndex: bigint;
  unlockBytes?: Uint8Array;
  earlyUnlockBytes?: Uint8Array;
}) {
  const unlockBurnHeight = rov(pox5.getBondL1UnlockHeight(bondIndex));
  const lockupScript = serializeLockupScript({
    stacker: staker,
    unlockBurnHeight,
    unlockBytes,
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

// /** Register the test signer with a valid signer key grant. Returns the signer key and pox address. */
export function registerSigner(
  { caller }: { caller: string } = { caller: deployer },
) {
  const signerSk = secp256k1.utils.randomSecretKey();
  const signerKey = secp256k1.getPublicKey(signerSk, true);
  const authId = grantAuthIdCounter++;
  const signature = signSignerKeyGrant({
    signerManager: testSigner.identifier,
    authId,
    signerSk,
  });
  txOk(
    testSigner.registerSelf({
      signerKey,
      signerManager: testSigner.identifier,
      authId,
      signerSig: signature,
    }),
    caller,
  );
  return { signerKey, signer: testSigner.identifier };
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
