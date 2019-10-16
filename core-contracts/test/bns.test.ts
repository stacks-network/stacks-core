import { Provider, ProviderRegistry, Receipt } from "@blockstack/clarity";
import { expect } from "chai";
import { BNSClient } from "../src/bns-client";

describe("BNSClient Test Suite", () => {
  let bns: BNSClient;
  let provider: Provider;

  const addresses = [
    "SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7",
    "S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE",
    "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR"
  ];
  const alice = addresses[0];
  const bob = addresses[1];
  const charlie = addresses[2];

  before(async () => {
    provider = await ProviderRegistry.createProvider();
    bns = new BNSClient(provider);
  });

  describe("Deploying an instance of the contract", () => {
    before(async () => {
      await bns.deployContract();
    });

    // it("should ...", async () => {
    //   const preorder = await bns.preorderNamespace("id", { sender: alice });
    //   console.log(preorder);
    // });
  });

  // before(async () => {
  //   await provider.mineBlock();
  // });

});
