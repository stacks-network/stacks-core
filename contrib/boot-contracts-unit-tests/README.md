# Boot contracts unit tests

Run unit tests with clarinet on boot contracts.

Contracts tests:

- [x] pox-4.clar


## About boot contract unit testing with Clarinet

- To really test contracts such as the pox contracts, we need to test the boot contracts embedded
into Clarinet. For example `ST000000000000000000002AMW42H.pox-4.clar`
- This mean that calling this contract will interact 
- Since the boot contracts are embedded into Clarinet, we only test the version of the contract
that is in Clarinet, and not the ones that actually live in the stacks-core repository.

We are able to get the boot contracts coverage thanks to this settings in `vitest.config.js`:
```js
  includeBootContracts: true,
  bootContractsPath: `${process.cwd()}/boot_contracts`,
```
A copy of the tested boot contracts is includedin this directory as well so that we are able to
compute and render the code coverage.
