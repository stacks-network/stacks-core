import {
  Client,
  Provider,
  Receipt,
  Result,
  NativeClarityBinProvider,
  Transaction
} from "@blockstack/clarity";
import {
  ExecutionError
} from "@blockstack/clarity/lib/providers/clarityBin";
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
    params: {
      sender: string
    }): Promise<Receipt> {
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
      method: {
        name: "namespace-preorder",
        args: [`${hashedNamespace}`, `u${STX}`]
      }
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
    params: {
      sender: string
    }): Promise<Receipt> {
    let priceFuncAsArgs = [
      `u${priceFunction.base}`,
      `u${priceFunction.coeff}`,
      ...priceFunction.buckets.map(bucket => `u${bucket}`),
      `u${priceFunction.nonAlphaDiscount}`,
      `u${priceFunction.noVowelDiscount}`
    ];
    const tx = this.createTransaction({
      method: {
        name: "namespace-reveal",
        args: [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(salt)}`, ...priceFuncAsArgs, `u${renewalRule}`, `'${nameImporter}`]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-import (namespace (buff 20))
  //              (name (buff 48))
  //              (zonefile-hash (buff 20)))
  async nameImport(namespace: string,
    name: string,
    beneficiary: string,
    zonefileHash: string,
    params: {
      sender: string
    }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: {
        name: "name-import",
        args: [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`, `'${beneficiary}`, `0x${this.toHexString(zonefileHash)}`]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (namespace-ready (namespace (buff 20)))
  async namespaceReady(namespace: string, params: {
    sender: string
  }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: {
        name: "namespace-ready",
        args: [`0x${this.toHexString(namespace)}`]
      }
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
    params: {
      sender: string
    }): Promise<Receipt> {
    let fqn = `${name}.${namespace}${salt}`;
    let sha256 = new shajs.sha256().update(fqn).digest();
    let hash160 = new ripemd160().update(sha256).digest('hex');
    let hashedFqn = `0x${hash160}`;
    const tx = this.createTransaction({
      method: {
        name: "name-preorder",
        args: [`${hashedFqn}`, `u${STX}`]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-register (namespace (buff 20))
  //                (name (buff 48))
  //                (salt (buff 20))
  //                (zonefile-hash (buff 20)))
  async nameRegister(namespace: string,
    name: string,
    salt: string,
    zonefileHash: string,
    params: {
      sender: string
    }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: {
        name: "name-register",
        args: [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`, `0x${this.toHexString(salt)}`, `0x${this.toHexString(zonefileHash)}`]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-update (namespace (buff 20))
  //              (name (buff 48))
  //              (zonefile-hash (buff 20)))
  async nameUpdate(namespace: string,
    name: string,
    zonefileHash: string,
    params: {
      sender: string
    }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: {
        name: "name-update",
        args: [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`, `0x${this.toHexString(zonefileHash)}`]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-transfer (namespace (buff 20))
  //                (name (buff 48))
  //                (new-owner principal)
  //                (zonefile-hash (optional (buff 20))))
  async nameTransfer(namespace: string,
    name: string,
    newOwner: string,
    zonefileHash: string | null,
    params: {
      sender: string
    }): Promise<Receipt> {
    const args = [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`, `'${newOwner}`];
    args.push(zonefileHash === null ? "none" : `(some\ 0x${this.toHexString(zonefileHash)})`);

    const tx = this.createTransaction({
      method: {
        name: "name-transfer",
        args: args
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-revoke (namespace (buff 20))
  //              (name (buff 48)))
  async nameRevoke(namespace: string,
    name: string,
    params: {
      sender: string
    }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: {
        name: "name-revoke",
        args: [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-renewal (namespace (buff 20))
  //               (name (buff 48))
  //               (stx-to-burn uint)
  //               (new-owner (optional principal))
  //               (zonefile-hash (optional (buff 20))))
  async nameRenewal(namespace: string,
    name: string,
    STX: number,
    newOwner: null | string,
    zonefileHash: null | string,
    params: {
      sender: string
    }): Promise<Receipt> {
    const args = [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`, `u${STX}`];
    args.push(newOwner === null ? "none" : `(some\ '${newOwner})`);
    args.push(zonefileHash === null ? "none" : `(some\ 0x${this.toHexString(zonefileHash)})`);

    const tx = this.createTransaction({
      method: {
        name: "name-renewal",
        args: args
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (get-name-zonefile (namespace (buff 20))
  //                    (name (buff 48)))
  async getNameZonefile(namespace: string,
    name: string,
    params: {
      sender: string
    }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: {
        name: "name-resolve",
        args: [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (can-name-be-registered (namespace (buff 20))
  //                         (name (buff 48))
  async canNameBeRegistered(namespace: string,
    name: string): Promise<Receipt> {
    const args = [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`];
    const query = this.createQuery({
      atChaintip: false,
      method: {
        name: "can-name-be-registered",
        args: args
      }
    });
    const res = await this.submitQuery(query);
    return res;
  }

    // (resolve-principal (owner principal)
    async resolvePrincipal(owner: string): Promise<Receipt> {
      const args = [`'${owner}`];
      const query = this.createQuery({
        atChaintip: true,
        method: {
          name: "resolve-principal",
          args: args
        }
      });
      const res = await this.submitQuery(query);
      return res;
    }

  // (get-name-price (namespace (buff 20))
  //                      (name (buff 48))
  async getNamePrice(namespace: string,
    name: string): Promise<Receipt> {
    const args = [`0x${this.toHexString(namespace)}`, `0x${this.toHexString(name)}`];
    const query = this.createQuery({
      atChaintip: false,
      method: {
        name: "get-name-price",
        args: args
      }
    });
    const res = await this.submitQuery(query);
    return res;
  }

  // (get-namespace-price (namespace (buff 20))
  async getNamespacePrice(namespace: string): Promise<Receipt> {
    const args = [`0x${this.toHexString(namespace)}`];
    const query = this.createQuery({
      atChaintip: false,
      method: {
        name: "get-namespace-price",
        args: args
      }
    });
    const res = await this.submitQuery(query);
    return res;
  }

  // (define-public (namespace-update-function-price (namespace (buff 20))
  // (p-func-base uint)
  // (p-func-coeff uint)
  // (p-func-b1 uint)
  // (p-func-b2 uint)
  // (p-func-b3 uint)
  // (p-func-b4 uint)
  // (p-func-b5 uint)
  // (p-func-b6 uint)
  // (p-func-b7 uint)
  // (p-func-b8 uint)
  // (p-func-b9 uint)
  // (p-func-b10 uint)
  // (p-func-b11 uint)
  // (p-func-b12 uint)
  // (p-func-b13 uint)
  // (p-func-b14 uint)
  // (p-func-b15 uint)
  // (p-func-b16 uint)
  // (p-func-non-alpha-discount uint)
  // (p-func-no-vowel-discount uint))
  async namespaceUpdatePriceFunction(
    namespace: string,
    priceFunction: PriceFunction,
    params: {
      sender: string
    }): Promise<Receipt> {
    let priceFuncAsArgs = [
      `u${priceFunction.base}`,
      `u${priceFunction.coeff}`,
      ...priceFunction.buckets.map(bucket => `u${bucket}`),
      `u${priceFunction.nonAlphaDiscount}`,
      `u${priceFunction.noVowelDiscount}`
    ];
    const tx = this.createTransaction({
      method: {
        name: "namespace-update-function-price",
        args: [`0x${this.toHexString(namespace)}`, ...priceFuncAsArgs]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  // (name-revoke (namespace (buff 20))
  //              (name (buff 48)))
  async namespaceRevokePriceFunctionUpdates(namespace: string,
    params: {
      sender: string
    }): Promise<Receipt> {
    const tx = this.createTransaction({
      method: {
        name: "namespace-revoke-function-price-edition",
        args: [`0x${this.toHexString(namespace)}`]
      }
    });
    await tx.sign(params.sender);
    const res = await this.submitTransaction(tx);
    return res;
  }

  async mineBlocks(blocks: number) {
    for (let index = 0; index < blocks; index++) {
      const query = this.createQuery({
        atChaintip: false,
        method: {
          name: "get-namespace-price",
          args: ['0x0000']
        }
      });
      const res = await this.submitQuery(query);
    }
  }

  toHexString(input: String): String {
    return Buffer.from(input).toString('hex');
  }
}