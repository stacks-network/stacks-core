use crate::vm::{types::PrincipalData, database::{STXBalance, v2::utils::*}, errors::InterpreterResult as Result};
use super::{super::structures::STXBalanceSnapshot, ClarityDb, blocks::ClarityDbBlocks};

pub trait ClarityDbStx: ClarityDb + ClarityDbBlocks {
    fn get_stx_balance_snapshot(
        &mut self,
        principal: &PrincipalData,
    ) -> Result<STXBalanceSnapshot<Self>> 
    where
        Self: Sized
    {
        let stx_balance = self.get_account_stx_balance(principal)?;
        let cur_burn_height = self.get_current_burnchain_block_height()? as u64;

        test_debug!("Balance of {} (raw={},locked={},unlock-height={},current-height={}) is {} (has_unlockable_tokens_at_burn_block={})",
            principal,
            stx_balance.amount_unlocked(),
            stx_balance.amount_locked(),
            stx_balance.unlock_height(),
            cur_burn_height,
            stx_balance.get_available_balance_at_burn_block(
                cur_burn_height, 
                self.get_v1_unlock_height()?, 
                self.get_v2_unlock_height()?, 
                self.get_v3_unlock_height()?
            ),
            stx_balance.has_unlockable_tokens_at_burn_block(
                cur_burn_height, 
                self.get_v1_unlock_height()?, 
                self.get_v2_unlock_height()?, 
                self.get_v3_unlock_height()?
            )
        );

        Ok(STXBalanceSnapshot::new(
            principal, 
            stx_balance, 
            cur_burn_height, 
            self
        ))
    }

    fn get_stx_balance_snapshot_genesis(
        &mut self,
        principal: &PrincipalData,
    ) -> Result<STXBalanceSnapshot<Self>> 
    where
        Self: Sized
    {
        let stx_balance = self.get_account_stx_balance(principal)?;
        let cur_burn_height = 0;

        test_debug!("Balance of {} (raw={},locked={},unlock-height={},current-height={}) is {} (has_unlockable_tokens_at_burn_block={})",
            principal,
            stx_balance.amount_unlocked(),
            stx_balance.amount_locked(),
            stx_balance.unlock_height(),
            cur_burn_height,
            stx_balance.get_available_balance_at_burn_block(
                cur_burn_height, 
                self.get_v1_unlock_height()?, 
                self.get_v2_unlock_height()?, 
                self.get_v3_unlock_height()?
            ),
            stx_balance.has_unlockable_tokens_at_burn_block(
                cur_burn_height, 
                self.get_v1_unlock_height()?, 
                self.get_v2_unlock_height()?, 
                self.get_v3_unlock_height()?
            )
        );

        Ok(STXBalanceSnapshot::new(
            principal, 
            stx_balance, 
            cur_burn_height, 
            self
        ))
    }

    fn get_account_stx_balance(
        &mut self, 
        principal: &PrincipalData
    ) -> Result<STXBalance> 
    where
        Self: Sized
    {
        let key = make_key_for_account_balance(principal);
        debug!("Fetching account balance"; "principal" => %principal.to_string());
        let result = self.get(&key)?;
        let balance = match result {
            None => STXBalance::zero(),
            Some(balance) => balance,
        };
        Ok(balance)
    }

    fn get_account_nonce(
        &mut self, 
        principal: &PrincipalData
    ) -> Result<u64> 
    where
        Self: Sized
    {
        let key = make_key_for_account_nonce(principal);
        let nonce = self.get(&key)?.unwrap_or(0);
        Ok(nonce)
    }

    fn set_account_nonce(
        &mut self, 
        principal: &PrincipalData, 
        nonce: u64
    ) -> Result<()> 
    where
        Self: Sized
    {
        let key = make_key_for_account_nonce(principal);
        self.put(&key, &nonce)
    }
}