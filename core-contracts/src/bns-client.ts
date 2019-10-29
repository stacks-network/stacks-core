import { Client, Provider, Receipt, Result } from "@blockstack/clarity";
import ripemd160 from 'ripemd160';
import shajs from 'sha.js';

export interface PriceFunction {
  buckets: number[],
  base: number,
  coeff: number,
  nonAlphaDiscount: number,
  noVoyelDiscount: number,
}

export class BNSClient extends Client {
  constructor(provider: Provider) {
    super("S1G2081040G2081040G2081040G208105NK8PE5.bns", "bns", provider);
  }


  // (namespace-preorder (hashed-namespace (buff 20))
  //                     (stx-to-burn uint))
  async namespacePreorder(namespace: string, 
                          salt: string,
                          STX: number, 
                          params: { sender: string }): Promise<Receipt> {
    let sha256 = new shajs.sha256().update(namespace).digest();
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
  //                   (namespace-version uint)
  //                   (price-function (tuple (buckets (list 16 uint)) (base uint) (coeff uint) (nonalpha-discount uint) (no-voyel-discount uint)))
  //                   (renewal-rule uint)
  //                   (name-importer principal))
  async namespaceReveal(namespace: string, 
                        namespaceVersion: number, 
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
      `u${priceFunction.noVoyelDiscount}`];
    const tx = this.createTransaction({
      method: { name: "namespace-reveal", args: [`"${namespace}"`, `u${namespaceVersion}`, `"${salt}"`, ...priceFuncAsArgs, `u${renewalRule}`, `'${nameImporter}`] }
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
                   zonefileContent: string, 
                   params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "name-import", args: [`"${namespace}"`, `"${name}"`, `"${zonefileContent}"`] }
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
    let fqn = `${name}.${namespace}`;
    let sha256 = new shajs.sha256().update(fqn).digest();
    let hash160 = new ripemd160().update(sha256).digest('hex');
    let hashedFqn = `0x${hash160}`;
    console.log(hashedFqn);
    const tx = this.createTransaction({
      method: { name: "name-preorder", args: [`${hashedFqn}`, `u${STX}`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-register (namespace (buff 20))
  //                (name (buff 16))
  //                (zonefile-content (buff 40960)))
  async nameRegister(namespace: string, 
                     name: string, 
                     salt: string,
                     zonefileContent: string,
                     params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "name-register", args: [`"${namespace}"`, `"${name}"`, `"${zonefileContent}"`] }
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
      method: { name: "name-register", args: [`"${namespace}"`, `"${name}"`, `"${zonefileContent}"`] }
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
                     zonefileContent: string, 
                     params: { sender: string }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: { name: "name-transfer", args: [`"${namespace}"`, `"${name}"`, `'${newOwner}`, `"${zonefileContent}"`] }
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
      method: { name: "name-transfer", args: [`"${namespace}"`, `"${name}"`] }
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
    const tx = this.createTransaction({
      method: { name: "name-renewal", args: [`"${namespace}"`, `"${name}"`, `${STX}`] }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // todo(ludo): implement these entrypoints
  // sponsored-name-register-batch
  // sponsored-name-update
  // sponsored-name-transfer
  // sponsored-name-revoke
}
