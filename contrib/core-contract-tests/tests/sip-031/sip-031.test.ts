import { project, accounts } from '../clarigen-types'; // where your [types.output] was specified
import { CoreNodeEventType, projectFactory } from '@clarigen/core';
import { filterEvents, rov, txErr, txOk } from '@clarigen/test';
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