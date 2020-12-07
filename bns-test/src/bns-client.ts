import { Client, Provider, Receipt, Result, NativeClarityBinProvider, Transaction } from "@blockstack/clarity";
import { ExecutionError } from "@blockstack/clarity/lib/providers/clarityBin";
import ripemd160 from 'ripemd160';
import shajs from 'sha.js';

export interface PriceFunction {
  buckets: number[],
  base: number,
  coeff: number,
  nonAlphaDiscount: number,
  noVowelDiscount: number,
}

export class BNSClient extends Client {
  constructor(provider: NativeClarityBinProvider) {
    super("S1G2081040G2081040G2081040G208105NK8PE5.bns", "../../src/chainstate/stacks/boot/bns", provider);
  }

  submitTransaction = async (tx: Transaction): Promise<Receipt> => {
    if (!tx.method || !tx.sender) {
      throw 'Invalid TX';
    }
    try {
      const res = await this.provider.execute(
        this.name,
        tx.method.name,
        tx.sender,
        ...tx.method.args
      );
      return res;
    } catch (error) {
      if (error instanceof ExecutionError) {
        return {
          success: false,
          error: error.commandOutput,
        }
      }
      throw error;
    }
  }

  // (namespace-preorder (hashed-namespace (buff 20))
  //                     (stx-to-burn uint))
  async namespacePreorder(namespace: string, 
                          salt: string,
                          STX: number, 
                          params: { sender: string }): Promise<Receipt> {
    if (namespace === '') {
      throw new Error("Namespace can't be empty");
    }
    if (STX <= 0) {
      throw new Error("STX should be non-zero positive");
    }

    let sha256 = new shajs.sha256().update(`${namespace}${salt}`).digest();
    let hash160 = new ripemd160().update(sha256).digest('hex');
    let hashedNamespace = `0x${hash160}`;
    const tx = this.createTransaction({
      method: { name: "namespace-preorder", args: [`${hashedNamespace}`, `u${STX}`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (namespace-reveal (namespace (buff 20))
  //                   (price-function (tuple (buckets (list 16 uint)) (base uint) (coeff uint) (nonalpha-discount uint) (no-vowel-discount uint)))
  //                   (lifetime uint)
  //                   (name-importer principal))
  async namespaceReveal(namespace: string, 
                        salt: string,
                        priceFunction: PriceFunction, 
                        renewalRule: number, 
                        nameImporter: string, 
                        params: { sender: string }): Promise<Receipt> {
    let priceFuncAsArgs = [
      `u${priceFunction.base}`, 
      `u${priceFunction.coeff}`, 
      ...priceFunction.buckets.map(bucket => `u${bucket}`), 
      `u${priceFunction.nonAlphaDiscount}`, 
      `u${priceFunction.noVowelDiscount}`];
    const tx = this.createTransaction({
      method: { name: "namespace-reveal", args: [`"${namespace}"`, `"${salt}"`, ...priceFuncAsArgs, `u${renewalRule}`, `'${nameImporter}`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-import (namespace (buff 20))
  //              (name (buff 16))
  //              (zonefile-content (buff 40960)))
  async nameImport(namespace: string, 
                   name: string,
                   beneficiary: string,
                   zonefileContent: string, 
                   params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "name-import", args: [`"${namespace}"`, `"${name}"`, `'${beneficiary}`, `"${zonefileContent}"`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (namespace-ready (namespace (buff 20)))
  async namespaceReady(namespace: string, params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "namespace-ready", args: [`"${namespace}"`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-preorder (hashed-fqn (buff 20))
  //                (stx-to-burn uint))
  async namePreorder(namespace: string,
                     name: string,
                     salt: string,
                     STX: number, 
                     params: { sender: string }): Promise<Receipt> {
    let fqn = `${name}.${namespace}${salt}`;
    let sha256 = new shajs.sha256().update(fqn).digest();
    let hash160 = new ripemd160().update(sha256).digest('hex');
    let hashedFqn = `0x${hash160}`;
    const tx = this.createTransaction({
      method: { name: "name-preorder", args: [`${hashedFqn}`, `u${STX}`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-register (namespace (buff 20))
  //                (name (buff 16))
  //                (salt (buff 20))
  //                (zonefile-content (buff 40960)))
  async nameRegister(namespace: string, 
                     name: string, 
                     salt: string,
                     zonefileContent: string,
                     params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "name-register", args: [`"${namespace}"`, `"${name}"`, `"${salt}"`, `"${zonefileContent}"`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-update (namespace (buff 20))
  //              (name (buff 16))
  //              (zonefile-content (buff 40960)))
  async nameUpdate(namespace: string, 
                   name: string, 
                   zonefileContent: string, 
                   params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "name-update", args: [`"${namespace}"`, `"${name}"`, `"${zonefileContent}"`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-transfer (namespace (buff 20))
  //                (name (buff 16))
  //                (new-owner principal)
  //                (zonefile-content (optional (buff 40960))))
  async nameTransfer(namespace: string, 
                     name: string, 
                     newOwner: string, 
                     zonefileContent: string|null, 
                     params: { sender: string }): Promise<Receipt> {
    const args = [`"${namespace}"`, `"${name}"`, `'${newOwner}`];
    args.push(zonefileContent === null ? "none" : `(some\ "${zonefileContent}")`);

    const tx = this.createTransaction({
      method: { name: "name-transfer", args: args }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-revoke (namespace (buff 20))
  //              (name (buff 16)))
  async nameRevoke(namespace: string, 
                   name: string, 
                   params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "name-revoke", args: [`"${namespace}"`, `"${name}"`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-renewal (namespace (buff 20))
  //               (name (buff 16))
  //               (stx-to-burn uint)
  //               (new-owner (optional principal))
  //               (zonefile-content (optional (buff 40960))))
  async nameRenewal(namespace: string, 
                    name: string, 
                    STX: number, 
                    newOwner: null|string, 
                    zonefileContent: null|string, 
                    params: { sender: string }): Promise<Receipt> {
    const args = [`"${namespace}"`, `"${name}"`, `u${STX}`];
    args.push(newOwner === null ? "none" : `(some\ '${newOwner})`);
    args.push(zonefileContent === null ? "none" : `(some\ "${zonefileContent}")`);
                  
    const tx = this.createTransaction({
      method: { name: "name-renewal", args: args }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (get-name-zonefile (namespace (buff 20))
  //                    (name (buff 16)))
  async getNameZonefile(namespace: string, 
                        name: string, 
                        params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "name-resolve", args: [`"${namespace}"`, `"${name}"`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  async mineBlocks(blocks: number) {
    for (let index = 0; index < blocks; index++) {
      const query = this.createQuery({
        atChaintip: false,
        method: { name: "compute-namespace-price?", args: ['0x0000'] }
      });
      const res = await this.submitQuery(query);
    }
  }
}
