import { project, accounts } from '../clarigen-types'; // where your [types.output] was specified
import {
  CoreNodeEventType,
  cvToValue,
  projectFactory,
  MAINNET_BURN_ADDRESS,
} from '@clarigen/core';
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
  txOk(
    indirectContract.transferStx(amount, contract.identifier),
    accounts.wallet_4.address,
  );
}

// Helper function to mint the initial 200M STX to the contract
function mintInitial() {
  // First make sure wallet_4 has enough STX to mint the initial amount
  txOk(
    indirectContract.transferStx(
      constants.INITIAL_MINT_AMOUNT / 2n,
      accounts.wallet_4.address,
    ),
    accounts.wallet_5.address,
  );
  txOk(
    indirectContract.transferStx(
      constants.INITIAL_MINT_AMOUNT / 2n,
      accounts.wallet_4.address,
    ),
    accounts.wallet_6.address,
  );
  // Mint the entire INITIAL_MINT_AMOUNT to the vesting contract
  mint(constants.INITIAL_MINT_AMOUNT);
}

function months(n: number) {
  return n * Number(constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS);
}

test('initial recipient should be the deployer', () => {
  const value = rov(contract.getRecipient());
  expect(value).toBe(accounts.deployer.address);
});

test('only the recipient can update the recipient', () => {
  const receipt = txErr(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.wallet_1.address,
  );

  expect(receipt.value).toBe(constants.ERR_NOT_ALLOWED);
});

test('recipient can update the recipient', () => {
  txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );

  const value = rov(contract.getRecipient());
  expect(value).toBe(accounts.wallet_1.address);
});

test('updated recipient can re-update the recipient', () => {
  txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );
  expect(rov(contract.getRecipient())).toBe(accounts.wallet_1.address);

  txOk(
    contract.updateRecipient(accounts.wallet_2.address),
    accounts.wallet_1.address,
  );
  expect(rov(contract.getRecipient())).toBe(accounts.wallet_2.address);
});

test('recipient cannot be updated from an indirect contract', () => {
  const receipt = txErr(
    indirectContract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );
  expect(receipt.value).toBe(constants.ERR_NOT_ALLOWED);
});

test('errors if claiming as a non-recipient', () => {
  const receipt = txErr(contract.claim(), accounts.wallet_1.address);
  expect(receipt.value).toBe(constants.ERR_NOT_ALLOWED);
});

test('initial recipient can claim', () => {
  mintInitial();
  const receipt = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(constants.INITIAL_MINT_IMMEDIATE_AMOUNT);

  const [event] = filterEvents(
    receipt.events,
    CoreNodeEventType.StxTransferEvent,
  );
  expect(event.data.amount).toBe(`${constants.INITIAL_MINT_IMMEDIATE_AMOUNT}`);
  expect(event.data.recipient).toBe(accounts.deployer.address);
  expect(event.data.sender).toBe(contract.identifier);
});

// Mint full initial amount first
test('updated recipient can claim', () => {
  mintInitial();
  const balance = rov(indirectContract.getBalance(contract.identifier));
  expect(balance).toBe(constants.INITIAL_MINT_AMOUNT);

  txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );
  const receipt = txOk(contract.claim(), accounts.wallet_1.address);
  expect(receipt.value).toBe(constants.INITIAL_MINT_IMMEDIATE_AMOUNT);

  expect(receipt.events.length).toBe(2);
  const stxTransferEvents = filterEvents(
    receipt.events,
    CoreNodeEventType.StxTransferEvent,
  );
  expect(stxTransferEvents.length).toBe(1);
  const [event] = stxTransferEvents;
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
    const stxPerIteration =
      (initialMintAmount - immediateAmount) /
      constants.INITIAL_MINT_VESTING_ITERATIONS;
    const vestingAmount = stxPerIteration * iterations;
    return immediateAmount + vestingAmount;
  }

  expect(rov(contract.calcClaimableAmount(deployBlockHeight))).toBe(
    immediateAmount,
  );

  function expectAmount(month: bigint) {
    const burnHeight = deployBlockHeight + month * 4383n;
    expect(rov(contract.calcClaimableAmount(burnHeight))).toBe(
      expectedAmount(burnHeight),
    );
  }

  for (let i = 1n; i < constants.INITIAL_MINT_VESTING_ITERATIONS; i++) {
    expectAmount(i);
  }
  // At 24+ months, the entire vesting bucket should be unlocked
  expect(
    rov(
      contract.calcClaimableAmount(
        deployBlockHeight + constants.INITIAL_MINT_VESTING_ITERATIONS * 4383n,
      ),
    ),
  ).toBe(initialMintAmount);
  expect(
    rov(contract.calcClaimableAmount(deployBlockHeight + 25n * 4383n)),
  ).toBe(initialMintAmount);
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
  const expected =
    constants.INITIAL_MINT_IMMEDIATE_AMOUNT +
    constants.INITIAL_MINT_VESTING_AMOUNT /
      constants.INITIAL_MINT_VESTING_ITERATIONS +
    100n * 1000000n;
  expect(receipt.value).toBe(expected);

  const [event] = filterEvents(
    receipt.events,
    CoreNodeEventType.StxTransferEvent,
  );
  expect(event.data.amount).toBe(expected.toString());
  expect(event.data.recipient).toBe(accounts.deployer.address);
  expect(event.data.sender).toBe(contract.identifier);

  // wait 4 months, also the contract gets 500 STX
  mint(500n * 1000000n);
  simnet.mineEmptyBlocks(months(4));
  const receipt2 = txOk(contract.claim(), accounts.deployer.address);
  const expected2 =
    (constants.INITIAL_MINT_VESTING_AMOUNT /
      constants.INITIAL_MINT_VESTING_ITERATIONS) *
      4n +
    500n * 1000000n;
  expect(receipt2.value).toBe(expected2);

  const [event2] = filterEvents(
    receipt2.events,
    CoreNodeEventType.StxTransferEvent,
  );
  expect(event2.data.amount).toBe(expected2.toString());
  expect(event2.data.recipient).toBe(accounts.deployer.address);

  // wait until end of vesting (20 more months), with an extra 1500 STX
  // calc remainder of unvested, to deal with integer division
  const vestedAlready =
    (constants.INITIAL_MINT_VESTING_AMOUNT /
      constants.INITIAL_MINT_VESTING_ITERATIONS) *
    5n;
  const unvested = constants.INITIAL_MINT_VESTING_AMOUNT - vestedAlready;
  const expected3 = unvested + 1500n * 1000000n;
  mint(1500n * 1000000n);
  simnet.mineEmptyBlocks(months(20));
  const receipt3 = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt3.value).toBe(expected3);

  const [event3] = filterEvents(
    receipt3.events,
    CoreNodeEventType.StxTransferEvent,
  );
  expect(event3.data.amount).toBe(expected3.toString());
  expect(event3.data.recipient).toBe(accounts.deployer.address);

  // wait 1 more month, with an extra 1000 STX
  // there is no more vested amount, so the extra 1000 STX should be claimed
  const expected4 = 1000n * 1000000n;
  mint(1000n * 1000000n);
  simnet.mineEmptyBlocks(months(1));
  const receipt4 = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt4.value).toBe(expected4);

  const [event4] = filterEvents(
    receipt4.events,
    CoreNodeEventType.StxTransferEvent,
  );
  expect(event4.data.amount).toBe(expected4.toString());
  expect(event4.data.recipient).toBe(accounts.deployer.address);
  expect(rov(indirectContract.getBalance(contract.identifier))).toBe(0n);
});

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
  const perIteration =
    constants.INITIAL_MINT_VESTING_AMOUNT /
    constants.INITIAL_MINT_VESTING_ITERATIONS;
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
  txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );

  // External party deposits 500 STX
  const extraDeposit = 500n * 1000000n;
  mint(extraDeposit);

  // Wallet_1 claims: should receive 1/24 of vesting bucket + 500 STX
  const perIteration =
    constants.INITIAL_MINT_VESTING_AMOUNT /
    constants.INITIAL_MINT_VESTING_ITERATIONS;
  const expected = perIteration + extraDeposit;
  const receipt = txOk(contract.claim(), accounts.wallet_1.address);
  expect(receipt.value).toBe(expected);

  // Validate transfer event
  const [evt] = filterEvents(
    receipt.events,
    CoreNodeEventType.StxTransferEvent,
  );
  expect(evt.data.amount).toBe(expected.toString());
  expect(evt.data.recipient).toBe(accounts.wallet_1.address);
  expect(evt.data.sender).toBe(contract.identifier);
});

test('calculating claimable amount at invalid block height returns 0', () => {
  mintInitial();
  const deployBlockHeight = rov(contract.getDeployBlockHeight());
  expect(rov(contract.calcClaimableAmount(deployBlockHeight - 1n))).toBe(0n);
});

test('print events are emitted when updating recipient', () => {
  const receipt = txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );
  expect(receipt.events.length).toBe(1);
  const [event] = filterEvents(receipt.events, CoreNodeEventType.ContractEvent);
  const printData = cvToValue<{
    topic: string;
    oldRecipient: string;
    newRecipient: string;
  }>(event.data.value);
  expect(printData.topic).toBe('update-recipient');
  expect(printData.oldRecipient).toBe(accounts.deployer.address);
  expect(printData.newRecipient).toBe(accounts.wallet_1.address);
});

test('print events are emitted when claiming', () => {
  mintInitial();
  const receipt = txOk(contract.claim(), accounts.deployer.address);
  const [event] = filterEvents(receipt.events, CoreNodeEventType.ContractEvent);
  const printData = cvToValue<{
    topic: string;
    claimable: string;
    recipient: string;
  }>(event.data.value);
  expect(printData.topic).toBe('claim');
  expect(printData.claimable).toBe(constants.INITIAL_MINT_IMMEDIATE_AMOUNT);
  expect(printData.recipient).toBe(accounts.deployer.address);
});

test('claiming after waiting more than 1 month', () => {
  mintInitial();
  simnet.mineEmptyBlocks(months(1));
  const receipt = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(
    constants.INITIAL_MINT_IMMEDIATE_AMOUNT +
      constants.INITIAL_MINT_VESTING_AMOUNT /
        constants.INITIAL_MINT_VESTING_ITERATIONS,
  );
});

test('recipient cannot be set to a non-standard address', () => {
  const mainnetStandard = MAINNET_BURN_ADDRESS;
  const standardReceipt = txErr(
    contract.updateRecipient(mainnetStandard),
    accounts.deployer.address,
  );
  expect(standardReceipt.value).toBe(constants.ERR_INVALID_RECIPIENT);

  const mainnetContract = `${MAINNET_BURN_ADDRESS}.blah`;
  const contractReceipt = txErr(
    contract.updateRecipient(mainnetContract),
    accounts.deployer.address,
  );
  expect(contractReceipt.value).toBe(constants.ERR_INVALID_RECIPIENT);
});

test('recipient can be set to a contract', () => {
  const contractAddr = `${accounts.deployer.address}.blah`;
  txOk(contract.updateRecipient(contractAddr), accounts.deployer.address);
  expect(rov(contract.getRecipient())).toBe(contractAddr);
});

test('multiple recipient changes in same block work correctly', () => {
  // Initial recipient is deployer
  expect(rov(contract.getRecipient())).toBe(accounts.deployer.address);

  // Change to wallet_1
  txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );
  expect(rov(contract.getRecipient())).toBe(accounts.wallet_1.address);

  // Change back to deployer in same block
  txOk(
    contract.updateRecipient(accounts.deployer.address),
    accounts.wallet_1.address,
  );
  expect(rov(contract.getRecipient())).toBe(accounts.deployer.address);
});

test('large extra deposit does not break vesting calculations', () => {
  mintInitial();

  // Add a large amount of extra STX (100M STX)
  const largeAmount = 100000000n * 1000000n; // 100 million STX
  mint(largeAmount);

  // Move forward 12 months
  simnet.mineEmptyBlocks(months(12));

  // Calculate expected: immediate + half vesting + large amount
  const expected =
    constants.INITIAL_MINT_IMMEDIATE_AMOUNT +
    (constants.INITIAL_MINT_VESTING_AMOUNT /
      constants.INITIAL_MINT_VESTING_ITERATIONS) *
      12n +
    largeAmount;

  const receipt = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(expected);
});

test('previous recipient cannot update the recipient', () => {
  txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );
  expect(rov(contract.getRecipient())).toBe(accounts.wallet_1.address);

  txErr(
    contract.updateRecipient(accounts.wallet_2.address),
    accounts.deployer.address,
  );
  expect(rov(contract.getRecipient())).toBe(accounts.wallet_1.address);
});

test('previous recipient cannot claim', () => {
  mintInitial();

  txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );

  txErr(contract.claim(), accounts.deployer.address);

  // Contract should still have the unvested portion
  const remainingBalance = rov(
    indirectContract.getBalance(contract.identifier),
  );
  expect(remainingBalance).toBe(constants.INITIAL_MINT_AMOUNT);
});

test('vesting calculation at exact boundary blocks', () => {
  mintInitial();
  const deployBlockHeight = rov(contract.getDeployBlockHeight());

  // Test at exact iteration boundaries
  for (let i = 1n; i <= constants.INITIAL_MINT_VESTING_ITERATIONS; i++) {
    const exactBoundary =
      deployBlockHeight + i * constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS;
    const claimable = rov(contract.calcClaimableAmount(exactBoundary));

    const expectedVested =
      i < constants.INITIAL_MINT_VESTING_ITERATIONS
        ? (constants.INITIAL_MINT_VESTING_AMOUNT /
            constants.INITIAL_MINT_VESTING_ITERATIONS) *
          i
        : constants.INITIAL_MINT_VESTING_AMOUNT;

    const expected = constants.INITIAL_MINT_IMMEDIATE_AMOUNT + expectedVested;
    expect(claimable).toBe(expected);
  }
});

test('vesting calculation one block before boundary', () => {
  mintInitial();
  const deployBlockHeight = rov(contract.getDeployBlockHeight());

  // Test one block before each iteration boundary
  for (let i = 1n; i <= constants.INITIAL_MINT_VESTING_ITERATIONS; i++) {
    const oneBlockBefore =
      deployBlockHeight +
      i * constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS -
      1n;
    const claimable = rov(contract.calcClaimableAmount(oneBlockBefore));

    // Should still be the previous iteration's amount
    const expectedVested =
      (i - 1n) *
      (constants.INITIAL_MINT_VESTING_AMOUNT /
        constants.INITIAL_MINT_VESTING_ITERATIONS);
    const expected = constants.INITIAL_MINT_IMMEDIATE_AMOUNT + expectedVested;
    expect(claimable).toBe(expected);
  }
});

test('vesting calculation one block after boundary', () => {
  mintInitial();
  const deployBlockHeight = rov(contract.getDeployBlockHeight());

  // Test one block after each iteration boundary
  for (let i = 1n; i < constants.INITIAL_MINT_VESTING_ITERATIONS; i++) {
    const oneBlockAfter =
      deployBlockHeight +
      i * constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS +
      1n;
    const claimable = rov(contract.calcClaimableAmount(oneBlockAfter));

    // Should still be the current iteration's amount
    const expectedVested =
      i *
      (constants.INITIAL_MINT_VESTING_AMOUNT /
        constants.INITIAL_MINT_VESTING_ITERATIONS);
    const expected = constants.INITIAL_MINT_IMMEDIATE_AMOUNT + expectedVested;
    expect(claimable).toBe(expected);
  }

  // Special case for the last iteration
  const oneBlockAfter =
    deployBlockHeight +
    constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS *
      constants.INITIAL_MINT_VESTING_ITERATIONS +
    1n;
  const claimable = rov(contract.calcClaimableAmount(oneBlockAfter));

  // Should still be the current iteration's amount
  const expectedVested = constants.INITIAL_MINT_AMOUNT;
  expect(claimable).toBe(expectedVested);
});

test('contract balance exactly equals vested amount (no extra funds)', () => {
  // Only mint the exact initial amount, no extra
  mintInitial();

  // Move to middle of vesting period (12 months)
  simnet.mineEmptyBlocks(months(12));

  const vested =
    (constants.INITIAL_MINT_VESTING_AMOUNT /
      constants.INITIAL_MINT_VESTING_ITERATIONS) *
    12n;
  // Should be able to claim immediate + half of vesting
  const expected = constants.INITIAL_MINT_IMMEDIATE_AMOUNT + vested;
  const receipt = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(expected);

  // Contract should still have the unvested portion
  const remainingBalance = rov(
    indirectContract.getBalance(contract.identifier),
  );
  const expectedRemaining = constants.INITIAL_MINT_VESTING_AMOUNT - vested;
  expect(remainingBalance).toBe(expectedRemaining);
});

test('multiple small extra deposits accumulate correctly', () => {
  mintInitial();

  // Add multiple small deposits over time
  mint(100n * 1000000n); // 100 STX
  simnet.mineEmptyBlocks(months(1));

  mint(200n * 1000000n); // 200 STX
  simnet.mineEmptyBlocks(months(1));

  mint(300n * 1000000n); // 300 STX
  simnet.mineEmptyBlocks(months(1));

  // Total extra: 600 STX, Total time: 3 months
  const extraAmount = 600n * 1000000n;
  const vestedAfter3Months =
    (constants.INITIAL_MINT_VESTING_AMOUNT /
      constants.INITIAL_MINT_VESTING_ITERATIONS) *
    3n;
  const expected =
    constants.INITIAL_MINT_IMMEDIATE_AMOUNT + vestedAfter3Months + extraAmount;

  const receipt = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(expected);
});

test('recipient change during vesting period preserves vested amounts', () => {
  mintInitial();

  // Original recipient claims immediate amount
  const firstClaim = txOk(contract.claim(), accounts.deployer.address);
  expect(firstClaim.value).toBe(constants.INITIAL_MINT_IMMEDIATE_AMOUNT);

  // Wait 6 months
  simnet.mineEmptyBlocks(months(6));

  // Change recipient
  txOk(
    contract.updateRecipient(accounts.wallet_1.address),
    accounts.deployer.address,
  );

  // New recipient should be able to claim 6 months of vesting
  const expectedVested =
    (constants.INITIAL_MINT_VESTING_AMOUNT /
      constants.INITIAL_MINT_VESTING_ITERATIONS) *
    6n;
  const secondClaim = txOk(contract.claim(), accounts.wallet_1.address);
  expect(secondClaim.value).toBe(expectedVested);
});

test('recipient can be updated from an indirect contract set as recipient', () => {
  txOk(
    contract.updateRecipient(indirectContract.identifier),
    accounts.deployer.address,
  );
  txOk(
    indirectContract.updateRecipientAsContract(accounts.wallet_1.address),
    accounts.wallet_1.address,
  );
  expect(rov(contract.getRecipient())).toBe(accounts.wallet_1.address);
});

test('claim can be called from an indirect contract set as recipient', () => {
  mintInitial();
  txOk(
    contract.updateRecipient(indirectContract.identifier),
    accounts.deployer.address,
  );
  let receipt = txOk(
    indirectContract.claimAsContract(),
    accounts.wallet_1.address,
  );
  expect(receipt.value).toBe(constants.INITIAL_MINT_IMMEDIATE_AMOUNT);
});

// -----------------------------------------------------------------------------
// Fuzz Testing - Randomized Tests
// -----------------------------------------------------------------------------

test('fuzz: random extra deposits at random times', () => {
  mintInitial();

  let totalExtraDeposited = 0n;
  let totalMonthsElapsed = 0;

  // Generate 10 random deposit/time combinations
  for (let i = 0; i < 10; i++) {
    // Random deposit between 1 and 1000 STX
    const randomDeposit =
      BigInt(Math.floor(Math.random() * 1000) + 1) * 1000000n;
    mint(randomDeposit);
    totalExtraDeposited += randomDeposit;

    // Random time advancement between 0 and 3 months
    const randomMonths = Math.floor(Math.random() * 4);
    if (randomMonths > 0) {
      simnet.mineEmptyBlocks(months(randomMonths));
      totalMonthsElapsed += randomMonths;
    }
  }

  // Cap at 24 months for vesting calculation
  const effectiveMonths = Math.min(totalMonthsElapsed, 24);
  const expectedVested =
    effectiveMonths < 24
      ? (constants.INITIAL_MINT_VESTING_AMOUNT /
          constants.INITIAL_MINT_VESTING_ITERATIONS) *
        BigInt(effectiveMonths)
      : constants.INITIAL_MINT_VESTING_AMOUNT;

  const expectedTotal =
    constants.INITIAL_MINT_IMMEDIATE_AMOUNT +
    expectedVested +
    totalExtraDeposited;

  const receipt = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(expectedTotal);

  // Verify balance consistency
  const remainingBalance = rov(
    indirectContract.getBalance(contract.identifier),
  );
  const expectedRemaining =
    effectiveMonths < 24
      ? constants.INITIAL_MINT_VESTING_AMOUNT - expectedVested
      : 0n;
  expect(remainingBalance).toBe(expectedRemaining);
});

test('fuzz: random recipient changes during vesting', () => {
  mintInitial();

  const wallets = [
    accounts.deployer.address,
    accounts.wallet_1.address,
    accounts.wallet_2.address,
    accounts.wallet_3.address,
  ];

  let currentRecipient: string = accounts.deployer.address;
  let currentRecipientIndex = 0;
  let totalMonthsElapsed = 0;

  // Perform random recipient changes over time
  for (let i = 0; i < 8; i++) {
    // Random time advancement
    const monthsToAdvance = Math.floor(Math.random() * 4) + 1; // 1-4 months
    simnet.mineEmptyBlocks(months(monthsToAdvance));
    totalMonthsElapsed += monthsToAdvance;

    if (totalMonthsElapsed >= 24) break;

    // Random recipient change
    const newRecipientIndex = Math.floor(Math.random() * wallets.length);
    if (newRecipientIndex !== currentRecipientIndex) {
      txOk(
        contract.updateRecipient(wallets[newRecipientIndex]),
        currentRecipient,
      );
      currentRecipient = wallets[newRecipientIndex];
      currentRecipientIndex = newRecipientIndex;
    }
  }

  // Final recipient should be able to claim all vested funds
  const expectedVested =
    totalMonthsElapsed < 24
      ? (constants.INITIAL_MINT_VESTING_AMOUNT /
          constants.INITIAL_MINT_VESTING_ITERATIONS) *
        BigInt(totalMonthsElapsed)
      : constants.INITIAL_MINT_VESTING_AMOUNT;

  // If balance is sufficient, we can claim the vested amount
  const receipt = txOk(contract.claim(), currentRecipient);
  expect(receipt.value).toBe(
    expectedVested + constants.INITIAL_MINT_IMMEDIATE_AMOUNT,
  );
});

test('fuzz: random tiny deposits', () => {
  mintInitial();

  let totalTinyDeposits = 0n;

  // Add many tiny deposits (1-10 micro-STX each)
  for (let i = 0; i < 100; i++) {
    const tinyAmount = BigInt(Math.floor(Math.random() * 10) + 1); // 1-10 micro-STX
    mint(tinyAmount);
    totalTinyDeposits += tinyAmount;
  }

  // Advance some time
  simnet.mineEmptyBlocks(months(6));

  const expectedVested =
    (constants.INITIAL_MINT_VESTING_AMOUNT /
      constants.INITIAL_MINT_VESTING_ITERATIONS) *
    6n;
  const expected =
    constants.INITIAL_MINT_IMMEDIATE_AMOUNT +
    expectedVested +
    totalTinyDeposits;

  const receipt = txOk(contract.claim(), accounts.deployer.address);
  expect(receipt.value).toBe(expected);

  // Verify the expected remaining balance
  const remainingBalance = rov(
    indirectContract.getBalance(contract.identifier),
  );
  expect(remainingBalance).toBe(
    constants.INITIAL_MINT_AMOUNT -
      constants.INITIAL_MINT_IMMEDIATE_AMOUNT -
      expectedVested,
  );
});

test('fuzz: stress test claim at random intervals', () => {
  mintInitial();

  let totalClaimed = 0n;
  let currentBlock = 0n;
  let currentMonth = 0n;
  let initialBalance = rov(
    indirectContract.getBalance(accounts.deployer.address),
  );
  let totalExtraDeposited = 0n;

  // Perform claims at random intervals with random extra deposits
  while (currentMonth < 24) {
    // Random extra deposit
    const extraDeposit = BigInt(Math.floor(Math.random() * 10000000000));
    if (extraDeposit > 0n) {
      mint(extraDeposit);
      totalExtraDeposited += extraDeposit;
    }

    // Random time advancement, up to 5 months
    const blocksToAdvance =
      Math.floor(
        Math.random() *
          Number(constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS) *
          5,
      ) + 1;
    simnet.mineEmptyBlocks(blocksToAdvance);
    currentBlock += BigInt(blocksToAdvance);
    currentMonth =
      currentBlock / constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS;

    const totalClaimable =
      currentMonth < 24
        ? (constants.INITIAL_MINT_VESTING_AMOUNT /
            constants.INITIAL_MINT_VESTING_ITERATIONS) *
            currentMonth +
          constants.INITIAL_MINT_IMMEDIATE_AMOUNT
        : constants.INITIAL_MINT_AMOUNT;
    const expectedClaimable =
      totalClaimable + totalExtraDeposited - totalClaimed;

    // Claim whatever is available
    const receipt = txOk(contract.claim(), accounts.deployer.address);
    totalClaimed += receipt.value;

    // Verify claim amount is correct
    expect(receipt.value).toBe(expectedClaimable);

    // Verify the account balance after claim
    const newBalance = rov(
      indirectContract.getBalance(accounts.deployer.address),
    );
    expect(newBalance).toBe(initialBalance + totalClaimed);
  }

  // After all claims, verify the final balance
  const finalBalance = rov(indirectContract.getBalance(contract.identifier));
  const expectedFinalBalance =
    currentMonth >= 24
      ? 0n
      : constants.INITIAL_MINT_AMOUNT -
        constants.INITIAL_MINT_IMMEDIATE_AMOUNT -
        currentMonth *
          (constants.INITIAL_MINT_VESTING_AMOUNT /
            constants.INITIAL_MINT_VESTING_ITERATIONS);

  // Total claimed + final balance should account for all deposited funds
  expect(finalBalance).toBe(expectedFinalBalance);
});
