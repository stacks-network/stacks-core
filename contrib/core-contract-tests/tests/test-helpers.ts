import { secp256k1 } from '@noble/curves/secp256k1.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { getAddressFromPublicKey } from '@stacks/transactions';

export function randomSecretKey(seed?: Uint8Array) {
  return secp256k1.utils.randomSecretKey(seed);
}

export function randomPublicKey(seed?: Uint8Array) {
  return secp256k1.getPublicKey(randomSecretKey(seed), true);
}

export function randomStacksAddress(
  network: 'mainnet' | 'testnet' = 'testnet',
  seed?: Uint8Array,
) {
  const pk = randomPublicKey(seed);
  return getAddressFromPublicKey(pk, network);
}

export function randomPoxAddress(seed?: Uint8Array) {
  const hash = ripemd160(seed ?? randomBytes(32));
  return {
    version: Uint8Array.from([0x01]),
    hashbytes: hash,
  };
}

export function mineUntil(blockHeight: number | bigint) {
  simnet.mineEmptyBurnBlocks(Number(blockHeight) - simnet.burnBlockHeight);
}
