// Drives pox-5 far enough to produce real, non-zero staker rewards in simnet,
// so the payout path can be tested instead of only the "nothing to claim" path.
//
// The moving parts, in order:
//   1. register the manager as a signer (needs a secp256k1 grant signature)
//   2. stakers `stake` STX through the manager
//   3. advance to the staked reward cycle
//   4. fund pox-5 with sBTC -- that IS the reward pot (`get-rewards` reads the
//      contract's sBTC balance minus staked and reserve)
//   5. `calculate-rewards` to turn the pot into rewards-per-token
import {
  Cl,
  ClarityValue,
  cvToValue,
  privateKeyToPublic,
  signMessageHashRsv,
} from "@stacks/transactions";

export const POX5 = "ST000000000000000000002AMW42H.pox-5";
export const SBTC = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4";
export const MANAGER = "signer-manager";

// deterministic test key for the signer-key grant
// trailing 01 marks the key as compressed, so the derived pubkey is 33 bytes
const SIGNER_PRIVKEY =
  "010101010101010101010101010101010101010101010101010101010101010101";

export const managerPrincipal = (deployer: string, manager: string = MANAGER) =>
  `${deployer}.${manager}`;

export function expectOk(cv: ClarityValue, label: string) {
  if (cv.type === "err") {
    throw new Error(`${label} failed: ${Cl.prettyPrint(cv)}`);
  }
  return cv;
}

/**
 * Register the manager contract as a pox-5 signer.
 *
 * `traitPrincipal` overrides the trait argument passed to `register-self`,
 * which otherwise is the manager itself. Pass a different contract to check
 * that registering on behalf of someone else is refused -- note the grant
 * signature is still built for `manager`, so the call gets far enough to reach
 * pox-5's `register-signer` rather than failing signature recovery first.
 */
export function registerSigner(
  deployer: string,
  manager: string = MANAGER,
  pox5: string = POX5,
  traitPrincipal?: string,
) {
  const signerKey = privateKeyToPublic(SIGNER_PRIVKEY);
  const authId = 1;

  const hashCv = simnet.callReadOnlyFn(
    pox5,
    "get-signer-grant-message-hash",
    [Cl.principal(managerPrincipal(deployer, manager)), Cl.uint(authId)],
    deployer,
  ).result;
  const raw = (hashCv as any).value;
  const messageHash =
    typeof raw === "string" ? raw : Buffer.from(raw).toString("hex");
  const sig = signMessageHashRsv({ messageHash, privateKey: SIGNER_PRIVKEY });

  const res = simnet.callPublicFn(
    manager,
    "register-self",
    [
      Cl.principal(traitPrincipal ?? managerPrincipal(deployer, manager)),
      Cl.bufferFromHex(signerKey),
      Cl.uint(authId),
      Cl.bufferFromHex(sig),
    ],
    deployer,
  );
  return { signerKey, result: res.result };
}

/** Move sBTC into pox-5; this is what `get-rewards` sees as the reward pot. */
export function fundRewards(
  from: string,
  amount: number,
  pox5: string = POX5,
) {
  return simnet.callPublicFn(
    `${SBTC}.sbtc-token`,
    "transfer",
    [Cl.uint(amount), Cl.principal(from), Cl.principal(pox5), Cl.none()],
    from,
  );
}

export const num = (cv: ClarityValue) => Number(cvToValue(cv, true));

export function currentCycle(sender: string, pox5: string = POX5): number {
  return num(
    simnet.callReadOnlyFn(pox5, "current-pox-reward-cycle", [], sender).result,
  );
}
