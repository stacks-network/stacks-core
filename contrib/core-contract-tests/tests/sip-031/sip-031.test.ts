import { project, accounts } from '../clarigen-types'; // where your [types.output] was specified
import { CoreNodeEventType, projectFactory } from '@clarigen/core';
import { filterEvents, rov, txErr, txOk } from '@clarigen/test';
import { test, expect } from 'vitest';

const contracts = projectFactory(project, 'simnet');
const contract = contracts.sip031;
const constants = contract.constants;
const indirectContract = contracts.sip031Indirect;

/**
 * "Mint" STX to the contract
 */
function mint(amount: number | bigint) {
  txOk(indirectContract.transferStx(amount, contract.identifier), accounts.wallet_4.address);
}

// Helper function to mint the initial 200M STX to the contract
function mintInitial() {
  // First make sure wallet_4 has enough STX to mint the initial amount
  txOk(indirectContract.transferStx(constants.INITIAL_MINT_AMOUNT / 2n, accounts.wallet_4.address), accounts.wallet_5.address);
  txOk(indirectContract.transferStx(constants.INITIAL_MINT_AMOUNT / 2n, accounts.wallet_4.address), accounts.wallet_6.address);
  // Mint the entire INITIAL_MINT_AMOUNT to the vesting contract
  mint(constants.INITIAL_MINT_AMOUNT);
}

function months(n: number) {
  return n * Number(constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS);
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
  mintInitial();
  const receipt = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(constants.INITIAL_MINT_IMMEDIATE_AMOUNT);

  const [event] = filterEvents(receipt.events, CoreNodeEventType.StxTransferEvent);
  expect(event.data.amount).toBe(`${constants.INITIAL_MINT_IMMEDIATE_AMOUNT}`);
  expect(event.data.recipient).toBe(accounts.deployer.address);
  expect(event.data.sender).toBe(contract.identifier);
});

// Mint full initial amount first
test('updated recipient can claim', () => {
  mintInitial();
  const balance = rov(indirectContract.getBalance(contract.identifier));
  expect(balance).toBe(constants.INITIAL_MINT_AMOUNT);

  txOk(contract.updateRecipient(accounts.wallet_1.address), accounts.deployer.address);
  const receipt = txOk(contract.claim(), accounts.wallet_1.address);
  expect(receipt.value).toBe(constants.INITIAL_MINT_IMMEDIATE_AMOUNT);

  expect(receipt.events.length).toBe(1);
  const [event] = filterEvents(receipt.events, CoreNodeEventType.StxTransferEvent);
  expect(event.data.amount).toBe(`${constants.INITIAL_MINT_IMMEDIATE_AMOUNT}`);
  expect(event.data.recipient).toBe(accounts.wallet_1.address);
  expect(event.data.sender).toBe(contract.identifier);
});

test('calculating vested amounts at a block height', () => {
  mintInitial();
  const deployBlockHeight = rov(contract.getDeployBlockHeight());

  const initialMintAmount = 200_000_000n * 1000000n; // 200,000,000 STX
  const immediateAmount = 100_000_000n * 1000000n; // 100,000,000 STX

  function expectedAmount(burnHeight: bigint) {
    const diff = burnHeight - deployBlockHeight;
    const iterations = diff / 4383n;
    const stxPerIteration = (initialMintAmount - immediateAmount) / 24n;
    const vestingAmount = stxPerIteration * iterations;
    return immediateAmount + vestingAmount;
  }

  expect(rov(contract.calcClaimableAmount(deployBlockHeight))).toBe(immediateAmount);

  function expectAmount(month: bigint) {
    const burnHeight = deployBlockHeight + month * 4383n;
    expect(rov(contract.calcClaimableAmount(burnHeight))).toBe(expectedAmount(burnHeight));
  }

  for (let i = 1n; i < 24n; i++) {
    expectAmount(i);
  }
  // At 24+ months, the entire vesting bucket should be unlocked
  expect(rov(contract.calcClaimableAmount(deployBlockHeight + 24n * 4383n))).toBe(initialMintAmount);
  expect(rov(contract.calcClaimableAmount(deployBlockHeight + 25n * 4383n))).toBe(initialMintAmount);
});

// -----------------------------------------------------------------------------
// Claim scenario 1:
// - contract gets 100 STX after initial mint
// - claim after 1 month
// - recipient should get 100M + vested + 100 STX
// -----------------------------------------------------------------------------
test('claim scenario 1', () => {
  mintInitial();
  mint(100n * 1000000n);
  simnet.mineEmptyBlocks(months(1));
  const receipt = txOk(contract.claim(), accounts.deployer.address);
  const expected = constants.INITIAL_MINT_IMMEDIATE_AMOUNT + constants.INITIAL_MINT_VESTING_AMOUNT / 24n + 100n * 1000000n;
  expect(receipt.value).toBe(expected);

  const [event] = filterEvents(receipt.events, CoreNodeEventType.StxTransferEvent);
  expect(event.data.amount).toBe(expected.toString());
  expect(event.data.recipient).toBe(accounts.deployer.address);
  expect(event.data.sender).toBe(contract.identifier);

  // wait 4 months, also the contract gets 500 STX
  mint(500n * 1000000n);
  simnet.mineEmptyBlocks(months(4));
  const receipt2 = txOk(contract.claim(), accounts.deployer.address);
  const expected2 = constants.INITIAL_MINT_VESTING_AMOUNT / 24n * 4n + 500n * 1000000n;
  expect(receipt2.value).toBe(expected2);

  const [event2] = filterEvents(receipt2.events, CoreNodeEventType.StxTransferEvent);
  expect(event2.data.amount).toBe(expected2.toString());
  expect(event2.data.recipient).toBe(accounts.deployer.address);

  // wait until end of vesting (20 more months), with an extra 1500 STX
  // calc remainder of unvested, to deal with integer division
  const vestedAlready = constants.INITIAL_MINT_VESTING_AMOUNT / 24n * 5n;
  const unvested = constants.INITIAL_MINT_VESTING_AMOUNT - vestedAlready;
  const expected3 = unvested + 1500n * 1000000n;
  mint(1500n * 1000000n);
  simnet.mineEmptyBlocks(months(20));
  const receipt3 = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt3.value).toBe(expected3);

  const [event3] = filterEvents(receipt3.events, CoreNodeEventType.StxTransferEvent);
  expect(event3.data.amount).toBe(expected3.toString());
  expect(event3.data.recipient).toBe(accounts.deployer.address);

  // wait 1 more month, with an extra 1000 STX
  // there is no more vested amount, so the extra 1000 STX should be claimed
  const expected4 = 1000n * 1000000n;
  mint(1000n * 1000000n);
  simnet.mineEmptyBlocks(months(1));
  const receipt4 = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt4.value).toBe(expected4);

  const [event4] = filterEvents(receipt4.events, CoreNodeEventType.StxTransferEvent);
  expect(event4.data.amount).toBe(expected4.toString());
  expect(event4.data.recipient).toBe(accounts.deployer.address);
  expect(rov(indirectContract.getBalance(contract.identifier))).toBe(0n);
})

// -----------------------------------------------------------------------------
// Edge-case: Claim when the contract holds *zero* balance should revert
// -----------------------------------------------------------------------------
test('claim with zero balance should error with ERR_NOTHING_TO_CLAIM', () => {
  // No minting has happened, contract balance == 0
  const receipt = txErr(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(constants.ERR_NOTHING_TO_CLAIM);
});

// -----------------------------------------------------------------------------
// Edge-case: Calling `claim` twice in the same block – second should fail
// -----------------------------------------------------------------------------
test('double claim in the same block reverts on second call', () => {
  mintInitial();

  // First claim succeeds and drains the immediate bucket
  const first = txOk(contract.claim(), accounts.deployer.address);
  expect(first.value).toBe(constants.INITIAL_MINT_IMMEDIATE_AMOUNT);

  // Second claim in the *same* block should have nothing left
  const second = txErr(contract.claim(), accounts.deployer.address);
  expect(second.value).toBe(constants.ERR_NOTHING_TO_CLAIM);
});

// -----------------------------------------------------------------------------
// Edge-case: Deposit exactly the amount that is still un-vested ("reserved")
//              -> nothing should be claimable.
// -----------------------------------------------------------------------------
test('deposit equal to reserved (unvested) amount is NOT claimable', () => {
  // `reserved` at deployment time equals the total unvested part (100 M STX)
  const reserved = constants.INITIAL_MINT_VESTING_AMOUNT;

  // Deposit *only* the reserved amount, without the initial 200 M mint
  mint(reserved);

  // No portion of this deposit is vested, so claim must revert
  const receipt = txErr(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(constants.ERR_NOTHING_TO_CLAIM);
});

// -----------------------------------------------------------------------------
// Edge-case: Integer-division rounding – last vesting iteration flushes the
//              remainder so that total withdrawn == 200 M STX.
// -----------------------------------------------------------------------------
test('final vesting iteration flushes rounding remainder', () => {
  mintInitial();

  // Advance 23 of 24 months
  simnet.mineEmptyBlocks(months(23));

  // First claim: immediate bucket + 23/24 of vesting bucket
  const perIteration = constants.INITIAL_MINT_VESTING_AMOUNT / constants.INITIAL_MINT_VESTING_ITERATIONS;
  const expectedFirst =
    constants.INITIAL_MINT_IMMEDIATE_AMOUNT + perIteration * 23n;
  const first = txOk(contract.claim(), accounts.deployer.address);
  expect(first.value).toBe(expectedFirst);

  // Advance the final month
  simnet.mineEmptyBlocks(months(1));

  // Second claim: should transfer *exactly* the remainder
  const expectedSecond = constants.INITIAL_MINT_AMOUNT - expectedFirst;
  expect(expectedSecond + expectedFirst).toBe(constants.INITIAL_MINT_AMOUNT);
  const second = txOk(contract.claim(), accounts.deployer.address);
  expect(second.value).toBe(expectedSecond);

  // Contract should now hold zero STX (no extras were ever deposited)
  expect(rov(indirectContract.getBalance(contract.identifier))).toBe(0n);
});

// -----------------------------------------------------------------------------
// Edge-case #5: Recipient change between deposits – new recipient should receive
//              the next vested tranche *plus* freshly deposited STX.
// -----------------------------------------------------------------------------
test('new recipient claims vested tranche plus extra deposit', () => {
  mintInitial();

  // Deployer immediately claims the instantaneous 100 M
  txOk(contract.claim(), accounts.deployer.address);

  // Mine one vesting iteration (1 month)
  simnet.mineEmptyBlocks(months(1));

  // Update recipient to wallet_1
  txOk(contract.updateRecipient(accounts.wallet_1.address), accounts.deployer.address);

  // External party deposits 500 STX
  const extraDeposit = 500n * 1000000n;
  mint(extraDeposit);

  // Wallet_1 claims: should receive 1/24 of vesting bucket + 500 STX
  const perIteration = constants.INITIAL_MINT_VESTING_AMOUNT / constants.INITIAL_MINT_VESTING_ITERATIONS;
  const expected = perIteration + extraDeposit;
  const receipt = txOk(contract.claim(), accounts.wallet_1.address);
  expect(receipt.value).toBe(expected);

  // Validate transfer event
  const [evt] = filterEvents(receipt.events, CoreNodeEventType.StxTransferEvent);
  expect(evt.data.amount).toBe(expected.toString());
  expect(evt.data.recipient).toBe(accounts.wallet_1.address);
  expect(evt.data.sender).toBe(contract.identifier);
});