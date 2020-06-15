---
name: Testnet Bug
about: Use this template to submit Stacks 2.0 testnet bugs
title: "[TESTNET BUG]"
labels: bug, testnet
assignees: ''

---

## Describe the bug

A clear and concise description of what the bug is.

## Steps To Reproduce

Please provide detailed instructions (e.g. command line invocation with parameters) to reproduce the behavior.

## Expected behavior

A clear and concise description of what you expected to happen.

## Environment

 - OS: [e.g. Ubuntu / Debian]
 - Rust version
 - Output of `stacks-node version`

## Additional context

Please include any relevant stack traces, error messages and logs.

If you are encountering an issue with a smart contract, please include the smart contract code
that demonstrates the issue.

----

If you think this is eligible for a [bug bounty](https://testnet.blockstack.org/bounties), please check the relevant boxes below:

### Critical, Launch Blocking Bugs
**Consensus critical bugs**
- [ ] Can cause a chain split
- [ ] Can cause an invalid transaction to get mined
- [ ] Can cause an invalid block to get accepted
- [ ] Can cause a node to stall

**State corruption**
- [ ] Can modify a smart contract’s data maps and data vars without a `contract-call?

**Stolen funds**
- [ ] Any address losing STX without a corresponding transfer
- [ ] Modify token balances and NFT ownership in other contracts without a `contract-call?`

**Take control and/or bring network to a halt**
- [ ] Take control and/or bring network to a halt

### Major, Launch Blocking Bugs
**Major bugs**
- [ ] Performance or correctness bugs that don’t rise to P0 level
- [ ] Stress test or DoS attacks that slow things down enough
- [ ] Resource exhaustion
- [ ] Expected functionality doesn’t work in obvious ways (important to be super specific with this wording)


### Minor, Non-launch blocking bugs
**Minor bugs**
- [ ] Bugs in non-critical software (CLI, UI, etc) that doesn’t impact critical functionality
