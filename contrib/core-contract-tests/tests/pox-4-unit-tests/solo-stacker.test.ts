import { Cl, ClarityType, isClarityType } from "@stacks/transactions";
import { describe, expect, it, beforeEach, assert } from "vitest";

import { Pox4SignatureTopic, poxAddressToTuple } from "@stacks/stacking";
import { Simnet } from "@hirosystems/clarinet-sdk";
import {
  ERRORS,
  POX_CONTRACT,
  allowContractCaller,
  delegateStx,
  getPoxInfo,
  stackStx,
  stackers,
} from "./helpers";
import { address } from "@stacks/transactions/dist/cl";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const address1 = accounts.get("wallet_1")!;
const address2 = accounts.get("wallet_2")!;

const initialSTXBalance = 100_000_000 * 1e6;

const maxAmount = 20960000000000;

const getTotalStacked = (
  simnet: Simnet,
  poxContract: string,
  cycleId: number | bigint
) => {
  const totalStacked = simnet.callReadOnlyFn(
    poxContract,
    "get-total-ustx-stacked",
    [Cl.uint(cycleId)],
    address1
  );
  // @ts-ignore
  return totalStacked.result.value as bigint;
};

const stackingThreshold = 125000000000;

describe("pox-4", () => {
  beforeEach(async () => {
    simnet.setEpoch("3.0");
  });

  it("can call get-pox-info", async () => {
    const poxInfo = simnet.callReadOnlyFn(
      POX_CONTRACT,
      "get-pox-info",
      [],
      address1
    );
    assert(isClarityType(poxInfo.result, ClarityType.ResponseOk));
  });

  /*
    (stack-stx (amount-ustx uint)
      (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
      (start-burn-ht uint)
      (lock-period uint)
      (signer-sig (optional (buff 65)))
      (signer-key (buff 33))
      (max-amount uint)
      (auth-id uint))
  */

  describe("stack-stx", () => {
    it("can stack stxs", async () => {
      const account = stackers[0];
      const rewardCycle = 0;
      const burnBlockHeight = 1;
      const period = 10;
      const authId = 1;

      const sigArgs = {
        authId,
        maxAmount,
        rewardCycle,
        period,
        topic: Pox4SignatureTopic.StackStx,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      };
      const signerSignature = account.client.signPoxSignature(sigArgs);
      const signerKey = Cl.bufferFromHex(account.signerPubKey);
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      const stackStxArgs = [
        Cl.uint(ustxAmount),
        poxAddressToTuple(account.btcAddr),
        Cl.uint(burnBlockHeight),
        Cl.uint(period),
        Cl.some(Cl.bufferFromHex(signerSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];

      const response = simnet.callPublicFn(
        POX_CONTRACT,
        "stack-stx",
        stackStxArgs,
        address1
      );

      expect(response.result).toBeOk(
        Cl.tuple({
          "lock-amount": Cl.uint(187500000000),
          "signer-key": Cl.bufferFromHex(account.signerPubKey),
          stacker: Cl.principal(address1),
          "unlock-burn-height": Cl.uint(11550),
        })
      );

      const stxAccount = simnet.runSnippet(`(stx-account '${address1})`);
      expect(stxAccount).toBeTuple({
        locked: Cl.uint(ustxAmount),
        unlocked: Cl.uint(initialSTXBalance - ustxAmount),
        "unlock-height": Cl.uint(11550),
      });
    });

    it("unlocks stxs after period is ended", async () => {
      const account = stackers[0];
      const rewardCycle = 0;
      const burnBlockHeight = 1;
      const period = 2;
      const authId = 1;

      const sigArgs = {
        authId,
        maxAmount,
        rewardCycle,
        period,
        topic: Pox4SignatureTopic.StackStx,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      };
      const signerSignature = account.client.signPoxSignature(sigArgs);
      const signerKey = Cl.bufferFromHex(account.signerPubKey);
      const ustxAmount = initialSTXBalance * 0.2; // lock 20% of total balance

      const stackStxArgs = [
        Cl.uint(ustxAmount),
        poxAddressToTuple(account.btcAddr),
        Cl.uint(burnBlockHeight),
        Cl.uint(period),
        Cl.some(Cl.bufferFromHex(signerSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];

      const response = simnet.callPublicFn(
        POX_CONTRACT,
        "stack-stx",
        stackStxArgs,
        address1
      );
      expect(response.result).toHaveClarityType(ClarityType.ResponseOk);

      // try to transfer 90% of balance (should fail because 20% is locked)
      const { result: resultErr } = simnet.transferSTX(
        initialSTXBalance * 0.9,
        address2,
        address1
      );
      expect(resultErr).toBeErr(Cl.uint(1));

      simnet.mineEmptyBlocks(4000);

      const stxAccount = simnet.runSnippet(`(stx-account '${address1})`);
      expect(stxAccount).toBeTuple({
        locked: Cl.uint(0),
        unlocked: Cl.uint(initialSTXBalance),
        "unlock-height": Cl.uint(0),
      });

      // try to transfer 90% of balance (should succeed because period is ended)
      const { result: resultOk } = simnet.transferSTX(
        initialSTXBalance * 0.9,
        address2,
        address1
      );
      expect(resultOk).toBeOk(Cl.bool(true));
    });

    it("can stack stxs from multiple accounts with the same key", () => {
      const signerAccount = stackers[0];
      const rewardCycle = 0;
      const burnBlockHeight = 0;
      const period = 10;

      const signerAccountKey = Cl.bufferFromHex(signerAccount.signerPubKey);

      let i = 0;
      for (const account of stackers) {
        const authId = i;
        i++;
        const sigArgs = {
          authId,
          maxAmount,
          rewardCycle,
          period,
          topic: Pox4SignatureTopic.StackStx,
          poxAddress: account.btcAddr,
          signerPrivateKey: signerAccount.signerPrivKey,
        };
        const signerSignature = signerAccount.client.signPoxSignature(sigArgs);
        const ustxAmount = Math.floor(stackingThreshold * 1.5);

        const stackStxArgs = [
          Cl.uint(ustxAmount),
          poxAddressToTuple(account.btcAddr),
          Cl.uint(burnBlockHeight),
          Cl.uint(period),
          Cl.some(Cl.bufferFromHex(signerSignature)),
          signerAccountKey,
          Cl.uint(maxAmount),
          Cl.uint(authId),
        ];

        const response = simnet.callPublicFn(
          POX_CONTRACT,
          "stack-stx",
          stackStxArgs,
          account.stxAddress
        );

        expect(response.result).toBeOk(
          Cl.tuple({
            "lock-amount": Cl.uint(187500000000),
            "signer-key": Cl.bufferFromHex(signerAccount.signerPubKey),
            stacker: Cl.principal(account.stxAddress),
            "unlock-burn-height": Cl.uint(11550),
          })
        );

        const stxAccount = simnet.runSnippet(
          `(stx-account '${account.stxAddress})`
        );
        expect(stxAccount).toBeTuple({
          locked: Cl.uint(ustxAmount),
          unlocked: Cl.uint(initialSTXBalance - ustxAmount),
          "unlock-height": Cl.uint(11550),
        });
      }
    });

    it("returns an error for an invalid start height", async () => {
      const account = stackers[0];
      const burnBlockHeight = 2000;
      const period = 10;
      const authId = 1;
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      const response = stackStx(
        account,
        ustxAmount,
        burnBlockHeight,
        period,
        ustxAmount,
        authId,
        address1
      );

      expect(response.result).toBeErr(
        Cl.int(ERRORS.ERR_INVALID_START_BURN_HEIGHT)
      );
    });

    it("cannot be called indirectly by an unapproved caller", async () => {
      const account = stackers[0];
      const rewardCycle = 0;
      const burnBlockHeight = 1;
      const period = 10;
      const authId = 1;

      const sigArgs = {
        authId,
        maxAmount,
        rewardCycle,
        period,
        topic: Pox4SignatureTopic.StackStx,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      };
      const signerSignature = account.client.signPoxSignature(sigArgs);
      const signerKey = Cl.bufferFromHex(account.signerPubKey);
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      const stackStxArgs = [
        Cl.uint(ustxAmount),
        poxAddressToTuple(account.btcAddr),
        Cl.uint(burnBlockHeight),
        Cl.uint(period),
        Cl.some(Cl.bufferFromHex(signerSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];

      const response = simnet.callPublicFn(
        "indirect",
        "stack-stx",
        stackStxArgs,
        address1
      );

      expect(response.result).toBeErr(
        Cl.int(ERRORS.ERR_STACKING_PERMISSION_DENIED)
      );
    });

    it("can be called indirectly by an approved caller", async () => {
      const account = stackers[0];
      const rewardCycle = 0;
      const burnBlockHeight = 1;
      const period = 10;
      const authId = 1;

      allowContractCaller(`${deployer}.indirect`, null, address1);

      const sigArgs = {
        authId,
        maxAmount,
        rewardCycle,
        period,
        topic: Pox4SignatureTopic.StackStx,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      };
      const signerSignature = account.client.signPoxSignature(sigArgs);
      const signerKey = Cl.bufferFromHex(account.signerPubKey);
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      const stackStxArgs = [
        Cl.uint(ustxAmount),
        poxAddressToTuple(account.btcAddr),
        Cl.uint(burnBlockHeight),
        Cl.uint(period),
        Cl.some(Cl.bufferFromHex(signerSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];

      const response = simnet.callPublicFn(
        "indirect",
        "stack-stx",
        stackStxArgs,
        address1
      );

      expect(response.result).toBeOk(
        Cl.tuple({
          "lock-amount": Cl.uint(187500000000),
          "signer-key": Cl.bufferFromHex(account.signerPubKey),
          stacker: Cl.principal(account.stxAddress),
          "unlock-burn-height": Cl.uint(11550),
        })
      );

      const stxAccount = simnet.runSnippet(
        `(stx-account '${account.stxAddress})`
      );
      expect(stxAccount).toBeTuple({
        locked: Cl.uint(ustxAmount),
        unlocked: Cl.uint(initialSTXBalance - ustxAmount),
        "unlock-height": Cl.uint(11550),
      });
    });

    it("returns an error if the stacker is already stacked", async () => {
      const account = stackers[0];
      const burnBlockHeight = 0;
      const period = 10;
      const authId = 1;
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      stackStx(
        account,
        ustxAmount,
        burnBlockHeight,
        period,
        ustxAmount,
        authId,
        address1
      );

      const response = stackStx(
        account,
        ustxAmount,
        burnBlockHeight,
        period,
        ustxAmount,
        authId,
        address1
      );

      expect(response.result).toBeErr(
        Cl.int(ERRORS.ERR_STACKING_ALREADY_STACKED)
      );
    });

    it("returns an error if the stacker is already delegated", async () => {
      const account = stackers[0];
      const burnBlockHeight = 0;
      const period = 10;
      const authId = 1;
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      delegateStx(
        ustxAmount,
        address2,
        burnBlockHeight,
        account.btcAddr,
        address1
      );

      const response = stackStx(
        account,
        ustxAmount,
        burnBlockHeight,
        period,
        ustxAmount,
        authId,
        address1
      );

      expect(response.result).toBeErr(
        Cl.int(ERRORS.ERR_STACKING_ALREADY_DELEGATED)
      );
    });

    it("returns an error if the stacker has an insufficient balance", async () => {
      const account = stackers[0];
      const burnBlockHeight = 0;
      const period = 10;
      const authId = 1;
      const ustxAmount = simnet.getAssetsMap().get("STX")?.get(address1)! + 10n;

      const response = stackStx(
        account,
        ustxAmount,
        burnBlockHeight,
        period,
        ustxAmount,
        authId,
        address1
      );

      expect(response.result).toBeErr(
        Cl.int(ERRORS.ERR_STACKING_INSUFFICIENT_FUNDS)
      );
    });

    it("returns an error if the signature is already used", async () => {
      const account = stackers[0];
      const burnBlockHeight = 0;
      const period = 10;
      const authId = 1;
      const ustxAmount = Math.floor(stackingThreshold * 1.5);
      const rewardCycle = 0;

      const sigArgs = {
        authId,
        maxAmount,
        rewardCycle,
        period,
        topic: Pox4SignatureTopic.StackStx,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      };
      const signerSignature = account.client.signPoxSignature(sigArgs);

      simnet.callPrivateFn(
        POX_CONTRACT,
        "consume-signer-key-authorization",
        [
          poxAddressToTuple(account.btcAddr),
          Cl.uint(rewardCycle),
          Cl.stringAscii(Pox4SignatureTopic.StackStx),
          Cl.uint(period),
          Cl.some(Cl.bufferFromHex(signerSignature)),
          Cl.bufferFromHex(account.signerPubKey),
          Cl.uint(ustxAmount),
          Cl.uint(maxAmount),
          Cl.uint(authId),
        ],
        address1
      );

      const response = stackStx(
        account,
        ustxAmount,
        burnBlockHeight,
        period,
        maxAmount,
        authId,
        address1
      );

      expect(response.result).toBeErr(Cl.int(ERRORS.ERR_SIGNER_AUTH_USED));
    });
  });

  describe("stack-extend", () => {
    it("can extend stacking during the last stacking cycle", () => {
      const poxInfo = getPoxInfo();
      const cycleLength = Number(poxInfo.rewardCycleLength);

      const account = stackers[0];
      const burnBlockHeight = 1;
      const authId = account.authId;

      const stackSignature = account.client.signPoxSignature({
        authId,
        maxAmount,
        rewardCycle: 0,
        period: 2,
        topic: Pox4SignatureTopic.StackStx,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      });
      const signerKey = Cl.bufferFromHex(account.signerPubKey);
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      const stackStxArgs = [
        Cl.uint(ustxAmount),
        poxAddressToTuple(account.btcAddr),
        Cl.uint(burnBlockHeight),
        Cl.uint(2),
        Cl.some(Cl.bufferFromHex(stackSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];
      const response = simnet.callPublicFn(
        POX_CONTRACT,
        "stack-stx",
        stackStxArgs,
        address1
      );
      expect(response.result).toHaveClarityType(ClarityType.ResponseOk);

      // advance to cycle 1
      simnet.mineEmptyBlocks(cycleLength);

      // advance to cycle 2
      simnet.mineEmptyBlocks(cycleLength);
      // call stack-extend for 2 more cycles
      const extendSignature = account.client.signPoxSignature({
        authId,
        maxAmount,
        rewardCycle: 2,
        period: 2,
        topic: Pox4SignatureTopic.StackExtend,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      });
      const extendArgs = [
        Cl.uint(2),
        poxAddressToTuple(account.btcAddr),
        Cl.some(Cl.bufferFromHex(extendSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];
      const { result } = simnet.callPublicFn(
        POX_CONTRACT,
        "stack-extend",
        extendArgs,
        address1
      );
      expect(result).toBeOk(
        Cl.tuple({
          stacker: Cl.principal(address1),
          "unlock-burn-height": Cl.uint(cycleLength * 5),
        })
      );

      // advance to cycle 3
      simnet.mineEmptyBlocks(cycleLength);
      const totalCycle3 = getTotalStacked(simnet, POX_CONTRACT, 3);
      expect(totalCycle3).toBe(BigInt(ustxAmount));

      // advance to cycle 4
      simnet.mineEmptyBlocks(cycleLength);
      const totalCycle4 = getTotalStacked(simnet, POX_CONTRACT, 4);
      expect(totalCycle4).toBe(BigInt(ustxAmount));

      // advance to cycle 5
      simnet.mineEmptyBlocks(cycleLength);
      const totalCycle5 = getTotalStacked(simnet, POX_CONTRACT, 5);
      expect(totalCycle5).toBe(0n);
    });

    it("can extend stacking during any stacking cycle", () => {
      const poxInfo = getPoxInfo();
      const cycleLength = Number(poxInfo.rewardCycleLength);

      const account = stackers[0];
      const burnBlockHeight = 1;
      const authId = account.authId;

      const stackSignature = account.client.signPoxSignature({
        authId,
        maxAmount,
        rewardCycle: 0,
        period: 2,
        topic: Pox4SignatureTopic.StackStx,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      });
      const signerKey = Cl.bufferFromHex(account.signerPubKey);
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      const stackStxArgs = [
        Cl.uint(ustxAmount),
        poxAddressToTuple(account.btcAddr),
        Cl.uint(burnBlockHeight),
        Cl.uint(2),
        Cl.some(Cl.bufferFromHex(stackSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];
      const response = simnet.callPublicFn(
        POX_CONTRACT,
        "stack-stx",
        stackStxArgs,
        address1
      );
      expect(response.result).toHaveClarityType(ClarityType.ResponseOk);

      // advance to cycle 1
      simnet.mineEmptyBlocks(cycleLength);
      // call stack-extend for 2 more cycles
      const extendSignature = account.client.signPoxSignature({
        authId,
        maxAmount,
        rewardCycle: 1,
        period: 2,
        topic: Pox4SignatureTopic.StackExtend,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      });
      const extendArgs = [
        Cl.uint(2),
        poxAddressToTuple(account.btcAddr),
        Cl.some(Cl.bufferFromHex(extendSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];
      const { result } = simnet.callPublicFn(
        POX_CONTRACT,
        "stack-extend",
        extendArgs,
        address1
      );
      expect(result).toBeOk(
        Cl.tuple({
          stacker: Cl.principal(address1),
          "unlock-burn-height": Cl.uint(cycleLength * 5),
        })
      );

      // advance to cycle 2
      simnet.mineEmptyBlocks(cycleLength);
      const totalCycle2 = getTotalStacked(simnet, POX_CONTRACT, 2);
      expect(totalCycle2).toBe(BigInt(ustxAmount));

      // advance to cycle 3
      simnet.mineEmptyBlocks(cycleLength);
      const totalCycle3 = getTotalStacked(simnet, POX_CONTRACT, 3);
      expect(totalCycle3).toBe(BigInt(ustxAmount));

      // advance to cycle 4
      simnet.mineEmptyBlocks(cycleLength);
      const totalCycle4 = getTotalStacked(simnet, POX_CONTRACT, 4);
      expect(totalCycle4).toBe(BigInt(ustxAmount));

      // advance to cycle 5
      simnet.mineEmptyBlocks(cycleLength);
      const totalCycle5 = getTotalStacked(simnet, POX_CONTRACT, 5);
      expect(totalCycle5).toBe(0n);
    });

    it("can not extend stacking after stacking end", () => {
      const poxInfo = getPoxInfo();
      const cycleLength = Number(poxInfo.rewardCycleLength);

      const account = stackers[0];
      const burnBlockHeight = 1;
      const authId = account.authId;

      const stackSignature = account.client.signPoxSignature({
        authId,
        maxAmount,
        rewardCycle: 0,
        period: 2,
        topic: Pox4SignatureTopic.StackStx,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      });
      const signerKey = Cl.bufferFromHex(account.signerPubKey);
      const ustxAmount = Math.floor(stackingThreshold * 1.5);

      const stackStxArgs = [
        Cl.uint(ustxAmount),
        poxAddressToTuple(account.btcAddr),
        Cl.uint(burnBlockHeight),
        Cl.uint(2),
        Cl.some(Cl.bufferFromHex(stackSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];
      const response = simnet.callPublicFn(
        POX_CONTRACT,
        "stack-stx",
        stackStxArgs,
        address1
      );
      expect(response.result).toHaveClarityType(ClarityType.ResponseOk);

      // advance to cycle 3
      simnet.mineEmptyBlocks(cycleLength * 3);

      const extendSignature = account.client.signPoxSignature({
        authId,
        maxAmount,
        rewardCycle: 3,
        period: 2,
        topic: Pox4SignatureTopic.StackExtend,
        poxAddress: account.btcAddr,
        signerPrivateKey: account.signerPrivKey,
      });
      const extendArgs = [
        Cl.uint(2),
        poxAddressToTuple(account.btcAddr),
        Cl.some(Cl.bufferFromHex(extendSignature)),
        signerKey,
        Cl.uint(maxAmount),
        Cl.uint(authId),
      ];
      const { result } = simnet.callPublicFn(
        POX_CONTRACT,
        "stack-extend",
        extendArgs,
        address1
      );
      expect(result).toBeErr(Cl.int(26));
    });
  });
});
