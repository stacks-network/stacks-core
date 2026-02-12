import { secp256k1 } from "@noble/curves/secp256k1.js";
import { getAddressFromPublicKey } from "@stacks/transactions";

export function randomSecretKey(seed?: Uint8Array) {
  return secp256k1.utils.randomSecretKey(seed);
}

export function randomPublicKey(seed?: Uint8Array) {
  return secp256k1.getPublicKey(randomSecretKey(seed), true);
}

export function randomStacksAddress(
  network: "mainnet" | "testnet" = "testnet",
  seed?: Uint8Array,
) {
  const pk = randomPublicKey(seed);
  return getAddressFromPublicKey(pk, network);
}