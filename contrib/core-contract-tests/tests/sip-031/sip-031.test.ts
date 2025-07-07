import { project, accounts } from '../clarigen-types'; // where your [types.output] was specified
import { projectFactory } from '@clarigen/core';
import { rov, txErr, txOk } from '@clarigen/test';
import { test, expect } from 'vitest';

const contracts = projectFactory(project, 'simnet');
const contract = contracts.sip031;
const constants = contract.constants;

test('initial recipient should be the deployer', () => {
  const value = rov(contract.getRecipient());
  expect(value).toBe(accounts.deployer.address);
})

test('only the recigpient can update the recipient', () => {
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