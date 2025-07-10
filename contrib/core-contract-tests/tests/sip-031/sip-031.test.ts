import { project, accounts } from '../clarigen-types'; // where your [types.output] was specified
import { CoreNodeEventType, projectFactory } from '@clarigen/core';
import { filterEvents, rov, rovOk, txErr, txOk } from '@clarigen/test';
import { test, expect } from 'vitest';

const contracts = projectFactory(project, 'simnet');
const contract = contracts.sip031;
const constants = contract.constants;
const indirectContract = contracts.sip031Indirect;

function mint(amount: number | bigint) {
  txOk(indirectContract.transferStx(amount, contract.identifier), accounts.wallet_4.address);
}

test('initial recipient should be the deployer', () => {
  const value = rov(contract.getRecipient());
  expect(value).toBe(accounts.deployer.address);
})

test('only the recipient can update the recipient', () => {
  const receipt = txErr(contract.updateRecipient(accounts.wallet_1.address), accounts.wallet_1.address)

  expect(receipt.value).toBe(constants.ERR_NOT_ALLOWED);
});

test('recipient can update the recipient', () => {
  txOk(contract.updateRecipient(accounts.wallet_1.address), accounts.deployer.address)

  const value = rov(contract.getRecipient());
  expect(value).toBe(accounts.wallet_1.address);
});

test('updated recipient can re-update the recipient', () => {
  txOk(contract.updateRecipient(accounts.wallet_1.address), accounts.deployer.address)
  expect(rov(contract.getRecipient())).toBe(accounts.wallet_1.address);

  txOk(contract.updateRecipient(accounts.wallet_2.address), accounts.wallet_1.address)
  expect(rov(contract.getRecipient())).toBe(accounts.wallet_2.address);
});

test('recipient cannot be updated from an indirect contract', () => {
  const receipt = txErr(indirectContract.updateRecipient(accounts.wallet_1.address), accounts.deployer.address)
  expect(receipt.value).toBe(constants.ERR_NOT_ALLOWED);
});

test('errors if claiming as a non-recipient', () => {
  const receipt = txErr(contract.claim(), accounts.wallet_1.address)
  expect(receipt.value).toBe(constants.ERR_NOT_ALLOWED);
});

test('initial recipient can claim', () => {
  mint(100000000);
  const receipt = txOk(contract.claim(), accounts.deployer.address)
  expect(receipt.value).toBe(100000000n);
  const [event] = filterEvents(receipt.events, CoreNodeEventType.StxTransferEvent);
  expect(event.data.amount).toBe(`${100000000n}`);
  expect(event.data.recipient).toBe(accounts.deployer.address);
  expect(event.data.sender).toBe(contract.identifier);
});

test('updated recipient can claim', () => {
  mint(100000000);
  const balance = rov(indirectContract.getBalance(contract.identifier));
  expect(balance).toBe(100000000n);

  txOk(contract.updateRecipient(accounts.wallet_1.address), accounts.deployer.address)
  const receipt = txOk(contract.claim(), accounts.wallet_1.address)
  expect(receipt.value).toBe(100000000n);

  expect(receipt.events.length).toBe(1);
  const [event] = filterEvents(receipt.events, CoreNodeEventType.StxTransferEvent);
  expect(event.data.amount).toBe(`${100000000n}`);
  expect(event.data.recipient).toBe(accounts.wallet_1.address);
  expect(event.data.sender).toBe(contract.identifier);
});

test('calculating vested amounts at a block height', () => {
  const deployBlockHeight = rov(contract.getDeployBlockHeight());

  const initialMintAmount = 200_000_000n * 1000000n; // 200,000,000 STX
  const immediateAmount = 100_000_000n * 1000000n; // 100,000,000 STX
  const vestingAmount = initialMintAmount - immediateAmount;

  function expectedAmount(burnHeight: bigint) {
    const diff = burnHeight - deployBlockHeight;
    const iterations = diff / 4383n;
    const stxPerIteration = (initialMintAmount - immediateAmount) / 24n;
    const vestingAmount = stxPerIteration * iterations;
    return immediateAmount + vestingAmount;
  }

  expect(rovOk(contract.calcVestedAmount(deployBlockHeight))).toBe(immediateAmount);

  function expectAmount(month: bigint) {
    const burnHeight = deployBlockHeight + month * 4383n;
    expect(rovOk(contract.calcVestedAmount(burnHeight))).toBe(expectedAmount(burnHeight));
  }
  expectAmount(1n);
  expectAmount(2n);
  expectAmount(3n);
  expectAmount(4n);
  expectAmount(5n);
  expectAmount(6n);
  expectAmount(7n);
  expectAmount(8n);
  expectAmount(9n);
  expectAmount(10n);
  expectAmount(11n);
  expectAmount(12n);
  expectAmount(13n);
  expectAmount(14n);
  expectAmount(15n);
  expectAmount(16n);
  expectAmount(17n);
  expectAmount(18n);
  expectAmount(19n);
  expectAmount(20n);
  expectAmount(21n);
  expectAmount(22n);
  expectAmount(23n);
  expectAmount(24n);

  expect(rovOk(contract.calcVestedAmount(deployBlockHeight + 25n * 4383n))).toBe(initialMintAmount);
});