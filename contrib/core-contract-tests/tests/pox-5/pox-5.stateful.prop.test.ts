import fc from 'fast-check';
import { accounts, project } from '../clarigen-types';
import { projectFactory } from '@clarigen/core';
import { test } from 'vitest';

import { AnnounceL1EarlyExitErrCannotAnnounce } from './commands/AnnounceL1EarlyExitErrCannotAnnounce';
import { AnnounceL1EarlyExitErrInPreparePhase } from './commands/AnnounceL1EarlyExitErrInPreparePhase';
import { AnnounceL1EarlyExitErrNotBondParticipant } from './commands/AnnounceL1EarlyExitErrNotBondParticipant';
import { AnnounceL1EarlyExitErrUnauthorized } from './commands/AnnounceL1EarlyExitErrUnauthorized';
import { AssertModelInvariants } from './commands/AssertModelInvariants';
import { AssertSignerInvariants } from './commands/AssertSignerInvariants';
import { AssertStakerInvariants } from './commands/AssertStakerInvariants';
import { CalculateRewards } from './commands/CalculateRewards';
import { CalculateRewardsErrActiveBondNotIncluded } from './commands/CalculateRewardsErrActiveBondNotIncluded';
import { CalculateRewardsErrAlreadyComputed } from './commands/CalculateRewardsErrAlreadyComputed';
import { CalculateRewardsErrBondNotActive } from './commands/CalculateRewardsErrBondNotActive';
import { CalculateRewardsErrInvalidOrdering } from './commands/CalculateRewardsErrInvalidOrdering';
import { ClaimRewards } from './commands/ClaimRewards';
import { ClaimRewardsErrNoClaimable } from './commands/ClaimRewardsErrNoClaimable';
import { ClaimStakerRewards } from './commands/ClaimStakerRewards';
import { ClaimStakerRewardsErrNoClaimable } from './commands/ClaimStakerRewardsErrNoClaimable';
import { DeploySigner } from './commands/DeploySigner';
import { FundRewards } from './commands/FundRewards';
import { GrantSignerKeyErrInvalidSignaturePubkey } from './commands/GrantSignerKeyErrInvalidSignaturePubkey';
import { GrantSignerKeyErrInvalidSignatureRecover } from './commands/GrantSignerKeyErrInvalidSignatureRecover';
import { GrantSignerKeyErrUnauthorizedRegistration } from './commands/GrantSignerKeyErrUnauthorizedRegistration';
import { MineBitcoinBlocks } from './commands/MineBlocks';
import { RegisterForBond } from './commands/RegisterForBond';
import { RegisterForBondErrAlreadyRegistered } from './commands/RegisterForBondErrAlreadyRegistered';
import { RegisterForBondErrAlreadyStaked } from './commands/RegisterForBondErrAlreadyStaked';
import { RegisterForBondErrBondAlreadyStarted } from './commands/RegisterForBondErrBondAlreadyStarted';
import { RegisterForBondErrBondNotFound } from './commands/RegisterForBondErrBondNotFound';
import { RegisterForBondErrGrantRevoked } from './commands/RegisterForBondErrGrantRevoked';
import { RegisterForBondErrInPreparePhase } from './commands/RegisterForBondErrInPreparePhase';
import { RegisterForBondErrInsufficientStx } from './commands/RegisterForBondErrInsufficientStx';
import { RegisterForBondErrInvalidBtcHeader } from './commands/RegisterForBondErrInvalidBtcHeader';
import { RegisterForBondErrNotAllowlisted } from './commands/RegisterForBondErrNotAllowlisted';
import { RegisterForBondErrRolloverTooEarly } from './commands/RegisterForBondErrRolloverTooEarly';
import { RegisterForBondErrSignerNotFound } from './commands/RegisterForBondErrSignerNotFound';
import { RegisterForBondErrTooMuchSats } from './commands/RegisterForBondErrTooMuchSats';
import { RegisterForBondRolloverFromStake } from './commands/RegisterForBondRolloverFromStake';
import { RegisterForBondViaContractCaller } from './commands/RegisterForBondViaContractCaller';
import { RegisterSigner } from './commands/RegisterSigner';
import { RegisterSignerErrGrantUsed } from './commands/RegisterSignerErrGrantUsed';
import { RegisterSignerErrGrantNotFound } from './commands/RegisterSignerErrGrantNotFound';
import { RegisterSignerErrUnauthorizedRegistration } from './commands/RegisterSignerErrUnauthorizedRegistration';
import { RevokeSignerGrant } from './commands/RevokeSignerGrant';
import { RevokeSignerGrantErrUnauthorized } from './commands/RevokeSignerGrantErrUnauthorized';
import { RevokeSignerGrantNonexistent } from './commands/RevokeSignerGrantNonexistent';
import { RotateSignerKey } from './commands/RotateSignerKey';
import { SetupBond } from './commands/SetupBond';
import { SetupBondErrAlreadySetup } from './commands/SetupBondErrAlreadySetup';
import { SetupBondErrStakerAlreadyAdded } from './commands/SetupBondErrStakerAlreadyAdded';
import { SetupBondErrTooLate } from './commands/SetupBondErrTooLate';
import { SetupBondErrTooSoon } from './commands/SetupBondErrTooSoon';
import { SetupBondErrUnauthorized } from './commands/SetupBondErrUnauthorized';
import { Stake } from './commands/Stake';
import { StakeErrAlreadyStaked } from './commands/StakeErrAlreadyStaked';
import { StakeErrGrantRevoked } from './commands/StakeErrGrantRevoked';
import { StakeErrInPreparePhase } from './commands/StakeErrInPreparePhase';
import { StakeErrInsufficientStx } from './commands/StakeErrInsufficientStx';
import { StakeErrInvalidNumCycles } from './commands/StakeErrInvalidNumCycles';
import { StakeErrInvalidStartBurnHeight } from './commands/StakeErrInvalidStartBurnHeight';
import { StakeErrRolloverTooEarly } from './commands/StakeErrRolloverTooEarly';
import { StakeErrSignerNotFound } from './commands/StakeErrSignerNotFound';
import { StakeExtend } from './commands/StakeExtend';
import { StakeRolloverFromBond } from './commands/StakeRolloverFromBond';
import { StakeUpdate } from './commands/StakeUpdate';
import { StakeUpdateErrGrantRevoked } from './commands/StakeUpdateErrGrantRevoked';
import { StakeUpdateErrInPreparePhase } from './commands/StakeUpdateErrInPreparePhase';
import { StakeUpdateErrInsufficientStx } from './commands/StakeUpdateErrInsufficientStx';
import { StakeUpdateErrInvalidNumCycles } from './commands/StakeUpdateErrInvalidNumCycles';
import { StakeUpdateErrInvalidOldSignerManager } from './commands/StakeUpdateErrInvalidOldSignerManager';
import { StakeUpdateErrNotStaking } from './commands/StakeUpdateErrNotStaking';
import { StakeUpdateErrSignerNotFound } from './commands/StakeUpdateErrSignerNotFound';
import { StakeViaContractCaller } from './commands/StakeViaContractCaller';
import { Unstake } from './commands/Unstake';
import { UnstakeErrInPreparePhase } from './commands/UnstakeErrInPreparePhase';
import { UnstakeErrInvalidOldSignerManager } from './commands/UnstakeErrInvalidOldSignerManager';
import { UnstakeErrNotStaking } from './commands/UnstakeErrNotStaking';
import { UnstakeSbtc } from './commands/UnstakeSbtc';
import { UnstakeSbtcErrInPreparePhase } from './commands/UnstakeSbtcErrInPreparePhase';
import { UnstakeSbtcErrInvalidAmount } from './commands/UnstakeSbtcErrInvalidAmount';
import { UnstakeSbtcErrInvalidOldSignerManager } from './commands/UnstakeSbtcErrInvalidOldSignerManager';
import { UnstakeSbtcErrNotBondParticipant } from './commands/UnstakeSbtcErrNotBondParticipant';
import { UnstakeViaContractCaller } from './commands/UnstakeViaContractCaller';
import { UpdateBondRegistration } from './commands/UpdateBondRegistration';
import { UpdateBondRegistrationErrGrantRevoked } from './commands/UpdateBondRegistrationErrGrantRevoked';
import { UpdateBondRegistrationErrInPreparePhase } from './commands/UpdateBondRegistrationErrInPreparePhase';
import { UpdateBondRegistrationErrInvalidOldSignerManager } from './commands/UpdateBondRegistrationErrInvalidOldSignerManager';
import { UpdateBondRegistrationErrNotBondParticipant } from './commands/UpdateBondRegistrationErrNotBondParticipant';
import { UpdateBondRegistrationErrSignerNotFound } from './commands/UpdateBondRegistrationErrSignerNotFound';
import { UpdateBondRegistrationErrUpdateBondSameSigner } from './commands/UpdateBondRegistrationErrUpdateBondSameSigner';
import { Model, Real } from './commands/types';
import {
  initialCommandStatistics,
  reportCommandRuns,
  trackCommandRun,
} from './commands/utils';
import { initSimnet } from '@stacks/clarinet-sdk';
import {
  POX5_BOOT_ID,
  REWARD_CYCLE_LENGTH,
  TOTAL_LIQUID_SUPPLY_USTX,
  initBootPox5,
  pox5,
  sbtcBalance,
  testSigner,
} from './pox-5-helpers';

const contracts = {
  ...projectFactory(project, 'simnet'),
  // Use the lock-aware boot pox-5: clarinet-sdk only applies STX locking to
  // ST0…AMW42H.pox-5, which signer-manager.clar / test-pox-5-signer.clar now
  // target. The local [contracts.pox-5] is not lock-aware in simnet.
  pox5,
};

// Local sweeps/replays override via env, e.g.:
//   FAST_CHECK_NUM_RUNS=1000 FAST_CHECK_SIZE=large FAST_CHECK_TIMEOUT_MS=600000 npx vitest run ...
//   FAST_CHECK_SEED=12345678 FAST_CHECK_REPLAY_PATH='...' npx vitest run ...
const NUM_RUNS = Number(process.env.FAST_CHECK_NUM_RUNS ?? 100);
const TEST_TIMEOUT_MS = Number(process.env.FAST_CHECK_TIMEOUT_MS ?? 120_000);
// Command-sequence length scale. CI default `medium`; sweeps crank to `large`.
const SIZE = (process.env.FAST_CHECK_SIZE ?? 'medium') as fc.Size;
const SEED =
  process.env.FAST_CHECK_SEED === undefined
    ? undefined
    : Number(process.env.FAST_CHECK_SEED);
const PATH = process.env.FAST_CHECK_PATH;
const REPLAY_PATH = process.env.FAST_CHECK_REPLAY_PATH;
// Shrinking can collapse any failure onto a non-idempotent command (one whose
// `check` lets it re-run against already-consumed state), masking the real
// divergence; noShrink shows what actually failed first.
const NO_SHRINK = process.env.FAST_CHECK_NO_SHRINK === '1';

type LabelledCommand = fc.Command<Model, Real> & { label: () => string };

function labelledCommand(
  label: string,
  commandArbitrary: fc.Arbitrary<fc.Command<Model, Real>>,
): { label: string; command: fc.Arbitrary<LabelledCommand> } {
  return {
    label,
    command: commandArbitrary.map((command) => {
      const labelled: LabelledCommand = {
        label: () => label,
        check: (model) => command.check(model),
        run: (model: Model, real: Real) => {
          trackCommandRun(model, labelled.label());
          command.run(model, real);
        },
        toString: () => command.toString(),
      };
      return labelled;
    }),
  };
}

test(
  'pox-5 stateful property test',
  async () => {
    const real: Real = {
      accounts,
      contracts,
      network: await initSimnet(),
    };

    // Configure the boot pox-5's burnchain params (the instance the commands
    // stake against).
    initBootPox5();

    // sBTC genesis balances come from the simnet plan; seed the model from the
    // live ledger so it matches whatever was allocated.
    const sbtcBalances = new Map(
      Object.values(accounts).map((a) => [a.address, sbtcBalance(a.address)]),
    );

    const commandRegistry = [
      labelledCommand('deploy-signer', DeploySigner()),
      labelledCommand(
        'grant-signer-key_err_unauthorized',
        GrantSignerKeyErrUnauthorizedRegistration(),
      ),
      labelledCommand(
        'grant-signer-key_err_invalid_sig_recover',
        GrantSignerKeyErrInvalidSignatureRecover(),
      ),
      labelledCommand(
        'grant-signer-key_err_invalid_sig_pubkey',
        GrantSignerKeyErrInvalidSignaturePubkey(),
      ),
      labelledCommand('register-signer', RegisterSigner(accounts)),
      labelledCommand(
        'register-signer_err_grant_used',
        RegisterSignerErrGrantUsed(accounts),
      ),
      labelledCommand(
        'register-signer_err_unauthorized',
        RegisterSignerErrUnauthorizedRegistration(),
      ),
      labelledCommand(
        'register-signer_err_grant_not_found',
        RegisterSignerErrGrantNotFound(),
      ),
      labelledCommand('rotate-signer-key', RotateSignerKey()),
      labelledCommand('revoke-signer-grant', RevokeSignerGrant()),
      labelledCommand(
        'revoke-signer-grant_nonexistent',
        RevokeSignerGrantNonexistent(),
      ),
      labelledCommand(
        'revoke-signer-grant_err_unauthorized',
        RevokeSignerGrantErrUnauthorized(accounts),
      ),
      labelledCommand('stake', Stake(accounts)),
      labelledCommand(
        'stake_rollover_from_bond',
        StakeRolloverFromBond(accounts),
      ),
      labelledCommand('stake_proxy', StakeViaContractCaller(accounts)),
      labelledCommand('stake-update', StakeUpdate(accounts)),
      labelledCommand('stake-extend', StakeExtend(accounts)),
      labelledCommand('unstake', Unstake(accounts)),
      labelledCommand('unstake_proxy', UnstakeViaContractCaller(accounts)),
      labelledCommand(
        'update-bond-registration',
        UpdateBondRegistration(accounts),
      ),
      labelledCommand(
        'update-bond-registration_err_not_bond_participant',
        UpdateBondRegistrationErrNotBondParticipant(accounts),
      ),
      labelledCommand(
        'update-bond-registration_err_in_prepare_phase',
        UpdateBondRegistrationErrInPreparePhase(accounts),
      ),
      labelledCommand(
        'update-bond-registration_err_invalid_old_signer',
        UpdateBondRegistrationErrInvalidOldSignerManager(accounts),
      ),
      labelledCommand(
        'update-bond-registration_err_same_signer',
        UpdateBondRegistrationErrUpdateBondSameSigner(accounts),
      ),
      labelledCommand(
        'update-bond-registration_err_signer_not_found',
        UpdateBondRegistrationErrSignerNotFound(accounts),
      ),
      labelledCommand(
        'update-bond-registration_err_grant_revoked',
        UpdateBondRegistrationErrGrantRevoked(accounts),
      ),
      labelledCommand('unstake-sbtc', UnstakeSbtc(accounts)),
      labelledCommand(
        'unstake-sbtc_err_not_bond_participant',
        UnstakeSbtcErrNotBondParticipant(accounts),
      ),
      labelledCommand(
        'unstake-sbtc_err_invalid_amount',
        UnstakeSbtcErrInvalidAmount(accounts),
      ),
      labelledCommand(
        'unstake-sbtc_err_in_prepare_phase',
        UnstakeSbtcErrInPreparePhase(accounts),
      ),
      labelledCommand(
        'unstake-sbtc_err_invalid_old_signer',
        UnstakeSbtcErrInvalidOldSignerManager(accounts),
      ),
      labelledCommand(
        'stake_err_already_staked',
        StakeErrAlreadyStaked(accounts),
      ),
      labelledCommand(
        'stake_err_signer_not_found',
        StakeErrSignerNotFound(accounts),
      ),
      labelledCommand(
        'stake_err_invalid_num_cycles',
        StakeErrInvalidNumCycles(accounts),
      ),
      labelledCommand(
        'stake_err_invalid_start_burn_height',
        StakeErrInvalidStartBurnHeight(accounts),
      ),
      labelledCommand(
        'stake_err_insufficient_stx',
        StakeErrInsufficientStx(accounts),
      ),
      labelledCommand(
        'stake_err_in_prepare_phase',
        StakeErrInPreparePhase(accounts),
      ),
      labelledCommand(
        'stake_err_grant_revoked',
        StakeErrGrantRevoked(accounts),
      ),
      labelledCommand(
        'stake_err_rollover_too_early',
        StakeErrRolloverTooEarly(accounts),
      ),
      labelledCommand(
        'stake-update_err_not_staking',
        StakeUpdateErrNotStaking(accounts),
      ),
      labelledCommand(
        'stake-update_err_in_prepare_phase',
        StakeUpdateErrInPreparePhase(accounts),
      ),
      labelledCommand(
        'stake-update_err_invalid_old_signer',
        StakeUpdateErrInvalidOldSignerManager(accounts),
      ),
      labelledCommand(
        'stake-update_err_signer_not_found',
        StakeUpdateErrSignerNotFound(accounts),
      ),
      labelledCommand(
        'stake-update_err_grant_revoked',
        StakeUpdateErrGrantRevoked(accounts),
      ),
      labelledCommand(
        'stake-update_err_invalid_num_cycles',
        StakeUpdateErrInvalidNumCycles(accounts),
      ),
      labelledCommand(
        'stake-update_err_insufficient_stx',
        StakeUpdateErrInsufficientStx(accounts),
      ),
      labelledCommand(
        'unstake_err_not_staking',
        UnstakeErrNotStaking(accounts),
      ),
      labelledCommand(
        'unstake_err_in_prepare_phase',
        UnstakeErrInPreparePhase(accounts),
      ),
      labelledCommand(
        'unstake_err_invalid_old_signer',
        UnstakeErrInvalidOldSignerManager(accounts),
      ),
      labelledCommand('setup-bond', SetupBond(accounts)),
      labelledCommand('register-for-bond', RegisterForBond(accounts)),
      labelledCommand(
        'register-for-bond_rollover_from_stake',
        RegisterForBondRolloverFromStake(accounts),
      ),
      labelledCommand(
        'register-for-bond_proxy',
        RegisterForBondViaContractCaller(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_bond_not_found',
        RegisterForBondErrBondNotFound(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_not_allowlisted',
        RegisterForBondErrNotAllowlisted(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_in_prepare_phase',
        RegisterForBondErrInPreparePhase(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_insufficient_stx',
        RegisterForBondErrInsufficientStx(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_bond_already_started',
        RegisterForBondErrBondAlreadyStarted(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_already_staked',
        RegisterForBondErrAlreadyStaked(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_already_registered',
        RegisterForBondErrAlreadyRegistered(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_rollover_too_early',
        RegisterForBondErrRolloverTooEarly(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_signer_not_found',
        RegisterForBondErrSignerNotFound(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_grant_revoked',
        RegisterForBondErrGrantRevoked(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_too_much_sats',
        RegisterForBondErrTooMuchSats(accounts),
      ),
      labelledCommand(
        'register-for-bond_err_invalid_btc_header',
        RegisterForBondErrInvalidBtcHeader(accounts),
      ),
      labelledCommand(
        'announce-l1-early-exit_err_cannot_announce',
        AnnounceL1EarlyExitErrCannotAnnounce(accounts),
      ),
      labelledCommand(
        'announce-l1-early-exit_err_in_prepare_phase',
        AnnounceL1EarlyExitErrInPreparePhase(accounts),
      ),
      labelledCommand(
        'announce-l1-early-exit_err_not_bond_participant',
        AnnounceL1EarlyExitErrNotBondParticipant(accounts),
      ),
      labelledCommand(
        'announce-l1-early-exit_err_unauthorized',
        AnnounceL1EarlyExitErrUnauthorized(accounts),
      ),
      labelledCommand(
        'setup-bond_err_unauthorized',
        SetupBondErrUnauthorized(accounts),
      ),
      labelledCommand(
        'setup-bond_err_already_setup',
        SetupBondErrAlreadySetup(accounts),
      ),
      labelledCommand(
        'setup-bond_err_staker_already_added',
        SetupBondErrStakerAlreadyAdded(accounts),
      ),
      labelledCommand('setup-bond_err_too_late', SetupBondErrTooLate(accounts)),
      labelledCommand('setup-bond_err_too_soon', SetupBondErrTooSoon(accounts)),
      labelledCommand('fund-rewards', FundRewards(accounts)),
      labelledCommand('calculate-rewards', CalculateRewards(accounts)),
      labelledCommand(
        'calculate-rewards_err_already_computed',
        CalculateRewardsErrAlreadyComputed(accounts),
      ),
      labelledCommand(
        'calculate-rewards_err_active_bond_not_included',
        CalculateRewardsErrActiveBondNotIncluded(accounts),
      ),
      labelledCommand(
        'calculate-rewards_err_invalid_ordering',
        CalculateRewardsErrInvalidOrdering(accounts),
      ),
      labelledCommand(
        'calculate-rewards_err_bond_not_active',
        CalculateRewardsErrBondNotActive(accounts),
      ),
      labelledCommand('claim-rewards', ClaimRewards(accounts)),
      labelledCommand(
        'claim-rewards_err_no_claimable',
        ClaimRewardsErrNoClaimable(accounts),
      ),
      labelledCommand('claim-staker-rewards', ClaimStakerRewards()),
      labelledCommand(
        'claim-staker-rewards_err_no_claimable',
        ClaimStakerRewardsErrNoClaimable(accounts),
      ),
      labelledCommand('mine-blocks', MineBitcoinBlocks()),
      labelledCommand('assert-signer-invariants', AssertSignerInvariants()),
      labelledCommand(
        'assert-staker-invariants',
        AssertStakerInvariants(accounts),
      ),
      labelledCommand(
        'assert-model-invariants',
        AssertModelInvariants(accounts),
      ),
    ];
    const invariants = commandRegistry.map(({ command }) => command);

    const model: Model = {
      stakers: new Map(),
      ustxDelegatedPerCycle: new Map(),
      signerDelegatedPerCycle: new Map(),
      signerPendingStakedPerCycle: new Map(),
      signerSetFirstPerCycle: new Map(),
      signerSetLastPerCycle: new Map(),
      signerSetItemsPerCycle: new Map(),
      stakerSignerCycleMemberships: new Map(),
      stakerSharesStakedForCycle: new Map(),
      bondTotalSharesForCycle: new Map(),
      bondSignerSharesForCycle: new Map(),
      bondStakerSharesForCycle: new Map(),
      // The default test-pox-5-signer is already deployed via Clarinet.toml;
      // DeploySigner adds further instances during the run.
      deployedSigners: new Set([testSigner.identifier]),
      signers: new Map(),
      usedGrants: new Set(),
      activeGrants: new Set(),
      burnBlockHeight: BigInt(real.network.burnBlockHeight),
      rewardCycleLength: REWARD_CYCLE_LENGTH,
      firstBurnHeight: 0n,
      prepareCycleLength: 10n,
      totalLiquidSupplyUstx: TOTAL_LIQUID_SUPPLY_USTX,
      bonds: new Map(),
      bondAllowances: new Map(),
      firstBondPeriodCycle: 1n,
      sbtcBalances,
      totalSbtcStaked: 0n,
      // The reward pool lives in the contract's sBTC balance; seed from the
      // live ledger so `get-rewards` derivations match from the first command.
      contractSbtcBalance: sbtcBalance(POX5_BOOT_ID),
      reserveBalance: 0n,
      lastAccountedRewardsOnly: 0n,
      lastRewardComputeHeight: 0n,
      rewardsPerTokenForCycle: new Map(),
      signerRewardsPerTokenSettled: new Map(),
      signerUnclaimedRewards: new Map(),
      signerRewardsPerTokenForCycle: new Map(),
      stakerRewardsPerTokenSettled: new Map(),
      stakerUnclaimedRewards: new Map(),
      bondMemberships: new Map(),
      bondTotalStaked: new Map(),
      statistics: initialCommandStatistics(
        commandRegistry.map(({ label }) => label),
      ),
    };

    fc.assert(
      fc.property(
        fc.commands(invariants, {
          size: SIZE,
          ...(REPLAY_PATH === undefined ? {} : { replayPath: REPLAY_PATH }),
        }),
        (cmds) => {
          const state = () => ({ model: model, real: real });
          fc.modelRun(state, cmds);
        },
      ),
      {
        numRuns: NUM_RUNS,
        verbose: 2,
        endOnFailure: NO_SHRINK,
        ...(SEED === undefined ? {} : { seed: SEED }),
        ...(PATH === undefined ? {} : { path: PATH }),
      },
    );

    reportCommandRuns(model);
  },
  TEST_TIMEOUT_MS,
);
