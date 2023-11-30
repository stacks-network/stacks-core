import { describe, expect, it } from "vitest";
import * as fs from "fs";
describe("test pox-4 source code for testnet", () => {
  it("should be the same for pox-4 + pox-testnet and pox-4-testnet", () => {
    const pox4Testnet = simnet.getContractSource("pox-4")!;
    const pox4 = fs
      .readFileSync("../../stackslib/src/chainstate/stacks/boot/pox-4.clar")
      .toString();
    const poxTestnet = fs
      .readFileSync(
        "../../stackslib/src/chainstate/stacks/boot/pox-testnet.clar"
      )
      .toString();
    const concatPox4Testnet = poxTestnet + "\n" + pox4;
    // uncomment next line to update pox-4-testnet.clar
    // fs.writeFileSync("contracts/pox/pox-4-testnet.clar", concatPox4Testnet);
    expect(concatPox4Testnet).toBe(pox4Testnet);
  });
});
