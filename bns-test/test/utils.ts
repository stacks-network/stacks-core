import { BNSClient } from "../src/bns-client";
export const mineBlocks = async (bns: BNSClient, blocks: number) => {
  await bns.mineBlocks(blocks);
}