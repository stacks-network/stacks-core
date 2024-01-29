import { Cl } from "@stacks/transactions";
import { beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

const accounts = simnet.getAccounts();
const alice = accounts.get("wallet_1")!;
const bob = accounts.get("wallet_2")!;
const charlie = accounts.get("wallet_3")!;

const cases = [
  {
    namespace: "blockstack",
    version: 1,
    salt: "0000",
    value: 640000000,
    namespaceOwner: alice,
    nameOwner: bob,
    priceFunction: [
      Cl.uint(4), // base
      Cl.uint(250), // coeff
      Cl.uint(7), // bucket 1
      Cl.uint(6), // bucket 2
      Cl.uint(5), // bucket 3
      Cl.uint(4), // bucket 4
      Cl.uint(3), // bucket 5
      Cl.uint(2), // bucket 6
      Cl.uint(1), // bucket 7
      Cl.uint(1), // bucket 8
      Cl.uint(1), // bucket 9
      Cl.uint(1), // bucket 10
      Cl.uint(1), // bucket 11
      Cl.uint(1), // bucket 12
      Cl.uint(1), // bucket 13
      Cl.uint(1), // bucket 14
      Cl.uint(1), // bucket 15
      Cl.uint(1), // bucket 16+
      Cl.uint(4), // nonAlphaDiscount
      Cl.uint(4), // noVowelDiscount
    ],
    renewalRule: 10,
    nameImporter: alice,
    zonefile: "0000",
  },
  {
    namespace: "id",
    version: 1,
    salt: "0000",
    value: 64000000000,
    namespaceOwner: alice,
    nameOwner: bob,
    priceFunction: [
      Cl.uint(4), // base
      Cl.uint(250), // coeff
      Cl.uint(6), // bucket 1
      Cl.uint(5), // bucket 2
      Cl.uint(4), // bucket 3
      Cl.uint(3), // bucket 4
      Cl.uint(2), // bucket 5
      Cl.uint(1), // bucket 6
      Cl.uint(0), // bucket 7
      Cl.uint(0), // bucket 8
      Cl.uint(0), // bucket 9
      Cl.uint(0), // bucket 10
      Cl.uint(0), // bucket 11
      Cl.uint(0), // bucket 12
      Cl.uint(0), // bucket 13
      Cl.uint(0), // bucket 14
      Cl.uint(0), // bucket 15
      Cl.uint(0), // bucket 16+
      Cl.uint(20), // nonAlphaDiscount
      Cl.uint(20), // noVowelDiscount
    ],
    renewalRule: 20,
    nameImporter: alice,
    zonefile: "1111",
  },
];

describe("test bns contract namespace errors", () => {
  it("should throw ERR_NAMESPACE_BLANK", () => {
    const { result } = simnet.callReadOnlyFn(
      "bns",
      "resolve-principal",
      [Cl.standardPrincipal(bob)],
      alice
    );
    expect(result).toBeErr(
      Cl.tuple({
        code: Cl.int(2013),
        name: Cl.none(),
      })
    );
  });

  it("should throw ERR_NAMESPACE_NOT_FOUND", () => {
    const { result } = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[1].namespace),
        Cl.bufferFromUtf8("bob"),
        Cl.bufferFromUtf8(cases[1].salt),
        Cl.bufferFromUtf8(cases[1].zonefile),
      ],
      cases[0].nameOwner
    );

    expect(result).toBeErr(Cl.int(1005));
  });
});

describe("preorder namespace", () => {
  it("should preorder a namespace", () => {
    const merged = new TextEncoder().encode(`${cases[1].namespace}${cases[1].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    const { result } = simnet.callPublicFn(
      "bns",
      "namespace-preorder",
      [Cl.buffer(ripemd160), Cl.uint(cases[1].value)],
      cases[1].namespaceOwner
    );
    expect(result).toBeOk(Cl.uint(144 + simnet.blockHeight));
  });
});

describe("namespace reveal workflow", () => {
  // preorder namespace
  beforeEach(() => {
    const merged = new TextEncoder().encode(`${cases[1].namespace}${cases[1].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    const { result } = simnet.callPublicFn(
      "bns",
      "namespace-preorder",
      [Cl.buffer(ripemd160), Cl.uint(cases[1].value)],
      cases[1].namespaceOwner
    );
    expect(result).toBeOk(Cl.uint(144 + simnet.blockHeight));
  });

  it("should reveal a namespace", () => {
    const { result } = simnet.callPublicFn(
      "bns",
      "namespace-reveal",
      [
        Cl.bufferFromUtf8(cases[1].namespace),
        Cl.bufferFromUtf8(cases[1].salt),
        ...cases[1].priceFunction,
        Cl.uint(cases[1].renewalRule),
        Cl.standardPrincipal(cases[1].nameImporter),
      ],
      cases[1].namespaceOwner
    );

    expect(result).toBeOk(Cl.bool(true));
  });

  it("fails if the namespace is not revealed", () => {
    simnet.callPublicFn(
      "bns",
      "namespace-reveal",
      [
        Cl.bufferFromUtf8(cases[1].namespace),
        Cl.bufferFromUtf8(cases[1].salt),
        ...cases[1].priceFunction,
        Cl.uint(cases[1].renewalRule),
        Cl.standardPrincipal(cases[1].nameImporter),
      ],
      cases[1].namespaceOwner
    );

    const name = "baobab";
    const merged = new TextEncoder().encode(`${name}.${cases[1].namespace}${cases[1].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    const preorder = simnet.callPublicFn(
      "bns",
      "name-preorder",
      [Cl.buffer(ripemd160), Cl.uint(100)],
      bob
    );
    expect(preorder.result).toBeOk(Cl.uint(144 + simnet.blockHeight));

    const register = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[1].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(cases[1].salt),
        Cl.bufferFromUtf8(cases[1].zonefile),
      ],
      bob
    );
    expect(register.result).toBeErr(Cl.int(2004));
  });

  it("can launch a namespace", () => {
    const merged = new TextEncoder().encode(`${cases[0].namespace}${cases[0].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn(
      "bns",
      "namespace-preorder",
      [Cl.buffer(ripemd160), Cl.uint(cases[0].value)],
      cases[0].namespaceOwner
    );

    simnet.callPublicFn(
      "bns",
      "namespace-reveal",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(cases[0].salt),
        ...cases[0].priceFunction,
        Cl.uint(cases[0].renewalRule),
        Cl.standardPrincipal(cases[0].nameImporter),
      ],
      cases[0].namespaceOwner
    );

    const { result } = simnet.callPublicFn(
      "bns",
      "namespace-ready",
      [Cl.bufferFromUtf8(cases[0].namespace)],
      cases[0].namespaceOwner
    );
    expect(result).toBeOk(Cl.bool(true));
  });
});

describe("name revealing workflow", () => {
  beforeEach(() => {
    // launch namespace
    const merged = new TextEncoder().encode(`${cases[0].namespace}${cases[0].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn(
      "bns",
      "namespace-preorder",
      [Cl.buffer(ripemd160), Cl.uint(cases[0].value)],
      cases[0].namespaceOwner
    );

    simnet.callPublicFn(
      "bns",
      "namespace-reveal",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(cases[0].salt),
        ...cases[0].priceFunction,
        Cl.uint(cases[0].renewalRule),
        Cl.standardPrincipal(cases[0].nameImporter),
      ],
      cases[0].namespaceOwner
    );

    const { result } = simnet.callPublicFn(
      "bns",
      "namespace-ready",
      [Cl.bufferFromUtf8(cases[0].namespace)],
      cases[0].namespaceOwner
    );
    expect(result).toBeOk(Cl.bool(true));
  });

  it("should fail if no preorder", () => {
    const name = "bob";
    const { result } = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(cases[0].salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      bob
    );
    expect(result).toBeErr(Cl.int(2001));
  });

  it("should fail if stx burnt is too low", () => {
    const name = "bub";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${cases[0].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn("bns", "name-preorder", [Cl.buffer(ripemd160), Cl.uint(2559999)], bob);

    const { result } = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8("bub"),
        Cl.bufferFromUtf8(cases[0].salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      bob
    );
    expect(result).toBeErr(Cl.int(2007));
  });

  it("should fail if existing pre-order", () => {
    const name = "Bob";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${cases[0].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn("bns", "name-preorder", [Cl.buffer(ripemd160), Cl.uint(2560000)], bob);

    const { result } = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(cases[0].salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      bob
    );
    expect(result).toBeErr(Cl.int(2022));
  });

  it("should successfully register", () => {
    const name = "bob";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${cases[0].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn("bns", "name-preorder", [Cl.buffer(ripemd160), Cl.uint(2560000)], bob);

    const register = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(cases[0].salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      bob
    );
    expect(register.result).toBeOk(Cl.bool(true));

    const resolvePrincipal = simnet.callReadOnlyFn(
      "bns",
      "resolve-principal",
      [Cl.standardPrincipal(bob)],
      alice
    );
    expect(resolvePrincipal.result).toBeOk(
      Cl.tuple({
        name: Cl.bufferFromUtf8("bob"),
        namespace: Cl.bufferFromUtf8("blockstack"),
      })
    );

    const nameResolve = simnet.callReadOnlyFn(
      "bns",
      "name-resolve",
      [Cl.bufferFromUtf8(cases[0].namespace), Cl.bufferFromUtf8(name)],
      alice
    );
    expect(nameResolve.result).toBeOk(
      Cl.tuple({
        owner: Cl.standardPrincipal(bob),
        ["zonefile-hash"]: Cl.bufferFromUtf8(cases[0].zonefile),
        ["lease-ending-at"]: Cl.some(Cl.uint(16)),
        ["lease-started-at"]: Cl.uint(6),
      })
    );
  });

  it("should fail registering twice", () => {
    const name = "bob";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${cases[0].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn("bns", "name-preorder", [Cl.buffer(ripemd160), Cl.uint(2560000)], bob);
    simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(cases[0].salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      bob
    );
    simnet.callReadOnlyFn("bns", "resolve-principal", [Cl.standardPrincipal(bob)], alice);

    const { result } = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(cases[0].salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      bob
    );
    expect(result).toBeErr(Cl.int(2004));
  });
});

describe("register a name again before and after expiration", () => {
  beforeEach(() => {
    // launch namespace
    const mergedNS = new TextEncoder().encode(`${cases[0].namespace}${cases[0].salt}`);
    const sha256NS = createHash("sha256").update(mergedNS).digest();
    const ripemd160NS = createHash("ripemd160").update(sha256NS).digest();
    simnet.callPublicFn(
      "bns",
      "namespace-preorder",
      [Cl.buffer(ripemd160NS), Cl.uint(cases[0].value)],
      cases[0].namespaceOwner
    );

    simnet.callPublicFn(
      "bns",
      "namespace-reveal",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(cases[0].salt),
        ...cases[0].priceFunction,
        Cl.uint(cases[0].renewalRule),
        Cl.standardPrincipal(cases[0].nameImporter),
      ],
      cases[0].namespaceOwner
    );

    simnet.callPublicFn(
      "bns",
      "namespace-ready",
      [Cl.bufferFromUtf8(cases[0].namespace)],
      cases[0].namespaceOwner
    );

    // register bob.blockstack
    const name = "bob";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${cases[0].salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn("bns", "name-preorder", [Cl.buffer(ripemd160), Cl.uint(2560000)], bob);

    simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(cases[0].salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      bob
    );
  });

  it("fails if someone else tries to register it", () => {
    const name = "bob";
    let salt = "1111";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    const preorder = simnet.callPublicFn(
      "bns",
      "name-preorder",
      [Cl.buffer(ripemd160), Cl.uint(2560000)],
      charlie
    );
    expect(preorder.result).toBeOk(Cl.uint(144 + simnet.blockHeight));

    const register = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      charlie
    );
    expect(register.result).toBeErr(Cl.int(2004));
  });

  it("should fail to register to register two names", () => {
    const name = "bobby";
    const salt = "1111";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn("bns", "name-preorder", [Cl.buffer(ripemd160), Cl.uint(2560000)], bob);

    const { result } = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromUtf8(cases[0].namespace),
        Cl.bufferFromUtf8(name),
        Cl.bufferFromUtf8(salt),
        Cl.bufferFromUtf8(cases[0].zonefile),
      ],
      bob
    );
    expect(result).toBeErr(Cl.int(3001));
  });

  it("should allow registering a new name after first name expiration", () => {
    simnet.mineEmptyBlocks(cases[0].renewalRule + 5001);

    const resolve = simnet.callReadOnlyFn(
      "bns",
      "resolve-principal",
      [Cl.standardPrincipal(bob)],
      alice
    );
    expect(resolve.result).toBeErr(
      Cl.tuple({
        code: Cl.int(2008),
        name: Cl.some(
          Cl.tuple({
            name: Cl.bufferFromUtf8("bob"),
            namespace: Cl.bufferFromUtf8("blockstack"),
          })
        ),
      })
    );

    const name = "bobby";
    const salt = "1111";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    const preorder = simnet.callPublicFn(
      "bns",
      "name-preorder",
      [Cl.buffer(ripemd160), Cl.uint(2560000)],
      bob
    );
    expect(preorder.result).toBeOk(Cl.uint(144 + simnet.blockHeight));

    const register = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromAscii(cases[0].namespace),
        Cl.bufferFromAscii(name),
        Cl.bufferFromAscii(salt),
        Cl.bufferFromAscii(cases[0].zonefile),
      ],
      bob
    );
    expect(register.result).toBeOk(Cl.bool(true));
  });

  it("should allow someone else to register after expiration", () => {
    simnet.mineEmptyBlocks(cases[0].renewalRule + 5001);

    const name = "bob";
    const salt = "2222";
    const merged = new TextEncoder().encode(`${name}.${cases[0].namespace}${salt}`);
    const sha256 = createHash("sha256").update(merged).digest();
    const ripemd160 = createHash("ripemd160").update(sha256).digest();
    simnet.callPublicFn("bns", "name-preorder", [Cl.buffer(ripemd160), Cl.uint(2560000)], charlie);
    const register = simnet.callPublicFn(
      "bns",
      "name-register",
      [
        Cl.bufferFromAscii(cases[0].namespace),
        Cl.bufferFromAscii(name),
        Cl.bufferFromAscii(salt),
        Cl.bufferFromAscii("CHARLIE"),
      ],
      charlie
    );
    expect(register.result).toBeOk(Cl.bool(true));

    const resolve = simnet.callReadOnlyFn(
      "bns",
      "name-resolve",
      [Cl.bufferFromAscii(cases[0].namespace), Cl.bufferFromAscii(name)],
      alice
    );
    expect(resolve.result).toBeOk(
      Cl.tuple({
        owner: Cl.standardPrincipal(charlie),
        ["zonefile-hash"]: Cl.bufferFromAscii("CHARLIE"),
        ["lease-ending-at"]: Cl.some(Cl.uint(5029)),
        ["lease-started-at"]: Cl.uint(5019),
      })
    );
  });
});
