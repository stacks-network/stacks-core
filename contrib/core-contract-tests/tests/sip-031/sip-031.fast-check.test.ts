import { project, accounts } from '../clarigen-types';
import { projectFactory } from '@clarigen/core';
import { rov, txErr, txOk } from '@clarigen/test';
import { test, expect } from 'vitest';
import * as fc from 'fast-check';
import { Cl } from '@stacks/transactions';

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

test('property: vesting calculations are always mathematically correct', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({
        min: 0,
        max: 100 * Number(constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS),
      }), // blocks elapsed (0-100 months)
      fc.bigInt({ min: 1n, max: 1000000n * 1000000n }), // extra deposit (1 micro-STX to 1M STX)
      async (blocksElapsed, extraDeposit) => {
        const manifestPath = global.options.clarinet.manifestPath;
        await simnet.initSession(process.cwd(), manifestPath);

        const monthsElapsed = Math.floor(
          blocksElapsed /
            Number(constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS),
        );

        mintInitial();

        // Add extra deposit
        if (extraDeposit > 0n) {
          mint(extraDeposit);
        }

        // Advance time
        if (monthsElapsed > 0) {
          simnet.mineEmptyBlocks(months(monthsElapsed));
        }

        // Calculate expected vested amount
        const effectiveMonths = Math.min(monthsElapsed, 24);
        const expectedVested =
          effectiveMonths < 24
            ? (constants.INITIAL_MINT_VESTING_AMOUNT /
                constants.INITIAL_MINT_VESTING_ITERATIONS) *
              BigInt(effectiveMonths)
            : constants.INITIAL_MINT_VESTING_AMOUNT;

        const expectedTotal =
          constants.INITIAL_MINT_IMMEDIATE_AMOUNT +
          expectedVested +
          extraDeposit;

        // Claim and verify
        const receipt = txOk(contract.claim(), accounts.deployer.address);

        // Properties that must always hold:
        // 1. Claimed amount should match calculation
        expect(receipt.value).toBe(expectedTotal);

        // 2. Remaining balance should be correct
        const remainingBalance = rov(
          indirectContract.getBalance(contract.identifier),
        );
        const expectedRemaining =
          effectiveMonths < 24
            ? constants.INITIAL_MINT_VESTING_AMOUNT - expectedVested
            : 0n;
        expect(remainingBalance).toBe(expectedRemaining);

        // 3. Total funds should be conserved
        const totalFunds = receipt.value + remainingBalance;
        expect(totalFunds).toBe(constants.INITIAL_MINT_AMOUNT + extraDeposit);
      },
    ),
    { numRuns: 50 },
  );
});

test('property: recipient changes maintain access control invariants', async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.integer({
        min: 0,
        max: 10 * Number(constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS),
      }), // blocks elapsed (0-10 months)
      fc.array(fc.integer({ min: 0, max: 9 }), { minLength: 1, maxLength: 20 }), // sequence of wallet indices
      async (blocksElapsed, walletIndices) => {
        // Reset state for each property test run
        const manifestPath = global.options.clarinet.manifestPath;
        await simnet.initSession(process.cwd(), manifestPath);

        const wallets = [
          accounts.deployer.address,
          accounts.wallet_1.address,
          accounts.wallet_2.address,
          accounts.wallet_3.address,
          accounts.wallet_4.address,
          accounts.wallet_5.address,
          accounts.wallet_6.address,
          accounts.wallet_7.address,
          accounts.wallet_8.address,
          accounts.wallet_9.address,
        ];

        let currentRecipient: string = accounts.deployer.address;

        // Perform sequence of recipient changes, advancing blocks between changes
        for (const walletIndex of walletIndices) {
          simnet.mineEmptyBlocks(blocksElapsed);
          const newRecipient = wallets[walletIndex];
          if (newRecipient !== currentRecipient) {
            txOk(contract.updateRecipient(newRecipient), currentRecipient);
            currentRecipient = newRecipient;
          }

          // Invariant: only current recipient can perform operations
          expect(rov(contract.getRecipient())).toBe(currentRecipient);

          const otherWallets = wallets.filter((w) => w !== currentRecipient);
          for (const otherWallet of otherWallets) {
            // Invariant: other wallets cannot update recipient
            const receipt = txErr(
              contract.updateRecipient(accounts.deployer.address),
              otherWallet,
            );
            expect(receipt.value).toBe(constants.ERR_NOT_ALLOWED);

            // Invariant: other wallets cannot claim
            const claimReceipt = txErr(contract.claim(), otherWallet);
            expect(claimReceipt.value).toBe(constants.ERR_NOT_ALLOWED);
          }
        }
      },
    ),
    { numRuns: 20 },
  );
});

test('property: calc-total-vested is always correct', () => {
  fc.assert(
    fc.property(
      fc.array(
        fc.bigInt({
          min: 0n,
          max: 1000n * constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS,
        }),
        {
          minLength: 2,
          maxLength: 50,
        },
      ),
      (burnHeights) => {
        const deployBlockHeight = rov(contract.getDeployBlockHeight());
        for (const burnHeight of burnHeights) {
          // This function cannot be called before the contract is deployed
          if (burnHeight < deployBlockHeight) {
            continue;
          }

          const diff = burnHeight - deployBlockHeight;
          const monthsElapsed =
            diff / constants.INITIAL_MINT_VESTING_ITERATION_BLOCKS;
          const expectedVested =
            constants.INITIAL_MINT_IMMEDIATE_AMOUNT +
            (monthsElapsed < 24
              ? (constants.INITIAL_MINT_VESTING_AMOUNT /
                  constants.INITIAL_MINT_VESTING_ITERATIONS) *
                BigInt(monthsElapsed)
              : constants.INITIAL_MINT_VESTING_AMOUNT);
          const actual = simnet.callPrivateFn(
            contract.identifier,
            'calc-total-vested',
            [Cl.uint(burnHeight)],
            accounts.deployer.address,
          );
          expect(actual.result).toBeUint(expectedVested);
        }
      },
    ),
    { numRuns: 1000 },
  );
});
