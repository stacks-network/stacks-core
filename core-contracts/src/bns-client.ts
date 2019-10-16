import { Client, Provider, Receipt, Result } from "@blockstack/clarity";

export class BNSClient extends Client {
  constructor(provider: Provider) {
    super("S1G2081040G2081040G2081040G208105NK8PE5.bns", "bns", provider);
  }

  async preorderNamespace(hashedNamespace: string, params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "preorder-namespace", args: [`"${hashedNamespace}"`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  async revealNamespace(namespace: string, params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "reveal-namespace", args: [`${namespace}`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }
}
