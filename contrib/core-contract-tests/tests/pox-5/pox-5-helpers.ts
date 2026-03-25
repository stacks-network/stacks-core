import * as BTC from '@scure/btc-signer';
import {
  Cl,
  createAddress,
  encodeStructuredDataBytes,
  signWithKey,
} from '@stacks/transactions';
import { hex } from '@scure/base';
import { projectErrors, projectFactory } from '@clarigen/core';
import { accounts, project } from '../clarigen-types';
import { rov, txOk } from '@clarigen/test';
import { sha256 } from '@noble/hashes/sha2.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { randomPoxAddress } from '../test-helpers';

const contracts = projectFactory(project, 'simnet');
export const pox5 = contracts.pox5;
export const errorCodes = projectErrors(project).pox5;
export const testPool = contracts.testPox5Pool;

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

export function signSignerKeyGrant({
  staker,
  poxAddr,
  authId,
  signerSk,
}: {
  staker: string;
  poxAddr: { version: Uint8Array; hashbytes: Uint8Array } | null;
  authId: bigint;
  signerSk: Uint8Array;
}) {
  const message = Cl.tuple({
    staker: Cl.principal(staker),
    topic: Cl.stringAscii('grant-authorization'),
    'pox-addr': poxAddr
      ? Cl.some(
          Cl.tuple({
            version: Cl.buffer(poxAddr.version),
            hashbytes: Cl.buffer(poxAddr.hashbytes),
          }),
        )
      : Cl.none(),
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
  staker,
  signerSk,
  poxAddr,
  authId,
}: {
  staker: string;
  signerSk: Uint8Array;
  poxAddr: { version: Uint8Array; hashbytes: Uint8Array } | null;
  authId: bigint;
}) {
  const signature = signSignerKeyGrant({
    staker,
    poxAddr,
    authId,
    signerSk,
  });
  txOk(
    pox5.grantSignerKey({
      signerKey: secp256k1.getPublicKey(signerSk, true),
      signerSig: signature,
      staker,
      authId,
      poxAddr,
    }),
    accounts.deployer.address,
  );
}

let grantAuthIdCounter = 1000n;

/** Create a signer key grant for `staker` (any pox-addr) and return the key pair. */
export function setupSigner(staker: string) {
  const signerSk = secp256k1.utils.randomSecretKey();
  const signerKey = secp256k1.getPublicKey(signerSk, true);
  const authId = grantAuthIdCounter++;
  createSignerKeyGrant({ staker, signerSk, poxAddr: null, authId });
  return { signerSk, signerKey };
}

/** Register the test pool with a valid signer key grant. Returns the signer key and pox address. */
export function registerPool({
  caller,
  poxAddr,
}: {
  caller: string;
  poxAddr?: { version: Uint8Array; hashbytes: Uint8Array };
}) {
  const { signerKey } = setupSigner(caller);
  const addr = poxAddr ?? randomPoxAddress();
  txOk(
    pox5.registerPool({
      poolOwner: testPool.identifier,
      signerKey,
      poxAddr: addr,
      signerSig: new Uint8Array(65),
      authId: 0,
    }),
    caller,
  );
  return { signerKey, poxAddr: addr };
}
