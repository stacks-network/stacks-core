import { Cl } from "@stacks/transactions";
import { beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";

const accounts = simnet.getAccounts();
const alice = accounts.get("wallet_1")!;
const bob = accounts.get("wallet_2")!;
const charlie = accounts.get("wallet_3")!;

const ERR_INVALID_AGGREGATE_PUBLIC_KEY = 10003;

describe("test pox-4-vote contract voting rounds", () => {
    it("should return none before any vote", () => {

        const { result: resultRound } = simnet.callReadOnlyFn(
            "pox-4-vote",
            "get-last-round",
            [Cl.uint(0)],
            alice,
        );
        expect(resultRound).toEqual(Cl.none());
    })

    it("should return none after invalid vote", () => {
        const { result: resultVote } = simnet.callPublicFn("pox-4-vote", "vote-for-aggregate-public-key",
            [Cl.bufferFromHex("12"), Cl.uint(0), Cl.uint(0),], alice);
        expect(resultVote).toEqual(Cl.error(Cl.uint(ERR_INVALID_AGGREGATE_PUBLIC_KEY)));

        const { result: resultRound } = simnet.callReadOnlyFn(
            "pox-4-vote",
            "get-last-round",
            [Cl.uint(0)],
            alice,
        );
        expect(resultRound).toEqual(Cl.none());

    })

    it("should return round after valid vote", () => {
        const { result: resultVote } = simnet.callPublicFn("pox-4-vote", "vote-for-aggregate-public-key",
            [Cl.bufferFromHex("123456789a123456789a123456789a123456789a123456789a123456789a010203"), Cl.uint(0), Cl.uint(0),], alice);
        expect(resultVote).toEqual(Cl.ok(Cl.bool(true)));

        const { result: resultRound } = simnet.callReadOnlyFn(
            "pox-4-vote",
            "get-last-round",
            [Cl.uint(0)],
            alice,
        );
        expect(resultRound).toEqual(Cl.some(Cl.uint(0)));

    })

    it("should return last round after valid votes for two rounds", () => {
        // Alice votes for cycle 0, round 0
        const { result: resultVoteAlice } = simnet.callPublicFn("pox-4-vote", "vote-for-aggregate-public-key",
            [Cl.bufferFromHex("123456789a123456789a123456789a123456789a123456789a123456789a010203"), Cl.uint(0), Cl.uint(0),], alice);
        expect(resultVoteAlice).toEqual(Cl.ok(Cl.bool(true)));

        // Bob votes for cycle 0, round 1
        const { result: resultVoteBob } = simnet.callPublicFn("pox-4-vote", "vote-for-aggregate-public-key",
            [Cl.bufferFromHex("123456789a123456789a123456789a123456789a123456789a123456789ab0b1b2"), Cl.uint(0), Cl.uint(1),], bob);
        expect(resultVoteBob).toEqual(Cl.ok(Cl.bool(true)));

        const { result: resultLastRound0 } = simnet.callReadOnlyFn(
            "pox-4-vote",
            "get-last-round",
            [Cl.uint(0)],
            alice,
        );
        expect(resultLastRound0).toEqual(Cl.some(Cl.uint(1)));
    })

    it("should return last round after valid votes for different cycles", () => {
        // Alice votes for cycle 0, round 1
        const { result: resultVoteAlice } = simnet.callPublicFn("pox-4-vote", "vote-for-aggregate-public-key",
            [Cl.bufferFromHex("123456789a123456789a123456789a123456789a123456789a123456789a010203"), Cl.uint(0), Cl.uint(1),], alice);
        expect(resultVoteAlice).toEqual(Cl.ok(Cl.bool(true)));

        // advance to next cycle
        simnet.mineEmptyBlocks(1050);

        // Bob votes for cycle 1, round 0
        const { result: resultVoteBob } = simnet.callPublicFn("pox-4-vote", "vote-for-aggregate-public-key",
            [Cl.bufferFromHex("123456789a123456789a123456789a123456789a123456789a123456789ab0b1b2"), Cl.uint(1), Cl.uint(0),], bob);
        expect(resultVoteBob).toEqual(Cl.ok(Cl.bool(true)));

        const { result: resultLastRound0 } = simnet.callReadOnlyFn(
            "pox-4-vote",
            "get-last-round",
            [Cl.uint(0)],
            alice,
        );
        expect(resultLastRound0).toEqual(Cl.some(Cl.uint(1)));


        const { result: resultLastRound1 } = simnet.callReadOnlyFn(
            "pox-4-vote",
            "get-last-round",
            [Cl.uint(1)],
            alice,
        );
        expect(resultLastRound1).toEqual(Cl.some(Cl.uint(0)));

    })
});