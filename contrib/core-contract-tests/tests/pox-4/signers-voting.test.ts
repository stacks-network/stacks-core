import { Cl } from "@stacks/transactions";
import { beforeEach, describe, expect, it } from "vitest";

const accounts = simnet.getAccounts();
const alice = accounts.get("wallet_1")!;
const bob = accounts.get("wallet_2")!;
const charlie = accounts.get("wallet_3")!;

const ERR_SIGNER_INDEX_MISMATCH = 10000;
const ERR_INVALID_SIGNER_INDEX = 10001;
const ERR_OUT_OF_VOTING_WINDOW = 10002
const ERR_OLD_ROUND = 10003;
const ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY = 10004;
const ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY = 10005;
const ERR_DUPLICATE_VOTE = 10006;
const ERR_INVALID_BURN_BLOCK_HEIGHT = 10007

const KEY_1 = "123456789a123456789a123456789a123456789a123456789a123456789a010203";
const KEY_2 = "123456789a123456789a123456789a123456789a123456789a123456789ab0b1b2";
const SIGNERS_VOTING = "signers-voting";

describe("test signers-voting contract voting rounds", () => {
    describe("test pox-info", () => {
        it("should return correct burn-height", () => {
            const { result:result1 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "reward-cycle-to-burn-height",
                [Cl.uint(1)],
                alice)
            expect(result1).toEqual(Cl.uint(1050))

            const { result:result2 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "reward-cycle-to-burn-height",
                [Cl.uint(2)],
                alice)
            expect(result2).toEqual(Cl.uint(2100))
        })

        it("should return correct reward-cycle", () => {
            const { result: result1 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "burn-height-to-reward-cycle",
                [Cl.uint(1)],
                alice)
            expect(result1).toEqual(Cl.uint(0))

            const { result: result2000 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "burn-height-to-reward-cycle",
                [Cl.uint(2000)],
                alice)
            expect(result2000).toEqual(Cl.uint(1))
        })

        it("should return true if in prepare phase", () => {
            const { result:result999 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "is-in-prepare-phase",
                [Cl.uint(999)],
                alice)
            expect(result999).toEqual(Cl.bool(false))

            const { result } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "is-in-prepare-phase",
                [Cl.uint(1000)],
                alice)
            expect(result).toEqual(Cl.bool(true))

            const { result: result1001 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "is-in-prepare-phase",
                [Cl.uint(1001)],
                alice)
            expect(result1001).toEqual(Cl.bool(true))


            const { result: result0 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "is-in-prepare-phase",
                [Cl.uint(1049)],
                alice)
            expect(result0).toEqual(Cl.bool(true))

            const { result: result1 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "is-in-prepare-phase",
                [Cl.uint(1050)],
                alice)
            expect(result1).toEqual(Cl.bool(false))

            const { result: result2 } = simnet.callReadOnlyFn(SIGNERS_VOTING,
                "is-in-prepare-phase",
                [Cl.uint(1051)],
                alice)
            expect(result2).toEqual(Cl.bool(false))
        })
    })

});