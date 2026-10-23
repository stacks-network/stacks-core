// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Bitcoin 25.1 replacement fee arithmetic, shared by fee raises and retargets.
//! This module does no signing, broadcasting, input selection or configuration I/O.

/// An invalid observation must not authorize a new spend.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum PricingError {
    #[error("invalid or unsupported Bitcoin replacement evidence")]
    InvalidEvidence,
    #[error("Bitcoin fee policy RPC unavailable")]
    RpcUnavailable,
    #[error("Bitcoin mempool has not finished loading")]
    MempoolLoading,
    #[error("replacement fee arithmetic overflow")]
    Overflow,
    #[error("replacement requires {required} sats, above absolute limit {limit}")]
    Limit { required: u64, limit: u64 },
}

/// One directly conflicting transaction (including a locally absent signed attempt).
#[derive(Clone, Copy, Debug)]
pub(super) struct Conflict {
    /// Fee including Bitcoin's local prioritisation delta, in sats.
    pub modified_fee: u64,
    /// Bitcoin policy virtual size, including sigop adjustment.
    pub vsize: u64,
}

/// Relay policy and the union of transactions evicted by the candidate.
#[derive(Clone, Debug)]
pub(super) struct ReplacementPolicy {
    /// Greater of mempool minimum and minimum relay rate, sats/kvB.
    pub minimum_sat_per_kvb: u64,
    /// Incremental relay rate, sats/kvB.
    pub incremental_sat_per_kvb: u64,
    /// Aggregate modified fees of the actual eviction set, not historical attempts.
    pub evicted_fee: u64,
    /// Direct conflicts; indirect descendants only contribute to evicted_fee.
    pub conflicts: Vec<Conflict>,
}

/// Convert Bitcoin's decimal BTC JSON amount to integer sats without floating point.
/// RPC/JSON normalization can emit exponent notation for small fees. Accept it
/// only when it represents an exact, nonnegative integer number of satoshis.
pub(super) fn bitcoin_amount(value: &serde_json::Value) -> Result<u64, PricingError> {
    let number = value.as_number().ok_or(PricingError::InvalidEvidence)?;
    let text = number.to_string();
    let (mantissa, exponent) = text.split_once(['e', 'E']).unwrap_or((&text, "0"));
    let exponent = exponent
        .parse::<i32>()
        .map_err(|_| PricingError::Overflow)?;
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(PricingError::InvalidEvidence);
    }
    let coefficient = whole
        .bytes()
        .chain(fraction.bytes())
        .try_fold(0_u128, |n, digit| {
            n.checked_mul(10)
                .and_then(|n| n.checked_add(u128::from(digit - b'0')))
                .ok_or(PricingError::Overflow)
        })?;
    if coefficient == 0 {
        return Ok(0);
    }
    let fractional_digits = i32::try_from(fraction.len()).map_err(|_| PricingError::Overflow)?;
    let scale = 8_i32
        .checked_add(exponent)
        .and_then(|n| n.checked_sub(fractional_digits))
        .ok_or(PricingError::Overflow)?;
    let factor = 10_u128
        .checked_pow(scale.unsigned_abs())
        .ok_or(PricingError::Overflow)?;
    let sats = if scale >= 0 {
        coefficient
            .checked_mul(factor)
            .ok_or(PricingError::Overflow)?
    } else {
        if coefficient % factor != 0 {
            return Err(PricingError::InvalidEvidence);
        }
        coefficient / factor
    };
    u64::try_from(sats).map_err(|_| PricingError::Overflow)
}

/// Bitcoin CFeeRate::GetFee for nonnegative rates, using exact integer ceiling.
pub(super) fn rate_fee(rate: u64, vsize: u64) -> Result<u64, PricingError> {
    let fee = u128::from(rate) * u128::from(vsize);
    u64::try_from(fee.div_ceil(1000)).map_err(|_| PricingError::Overflow)
}

/// Fresh commits may proceed on the operator's rate when policy observation is
/// unavailable. The 1 sat/vB backstop is not a claim about the current mempool.
/// Replacements MUST NOT use this fallback: their conflict evidence is mandatory.
pub(super) fn fresh_rate(
    configured: u64,
    observation: Result<&serde_json::Value, PricingError>,
) -> (u64, Option<PricingError>) {
    let floor = observation.and_then(|info| {
        if info["loaded"].as_bool() != Some(true) {
            return Err(PricingError::MempoolLoading);
        }
        Ok(bitcoin_amount(&info["mempoolminfee"])?.max(bitcoin_amount(&info["minrelaytxfee"])?))
    });
    match floor {
        Ok(floor) => (configured.max(floor), None),
        Err(error) => (configured.max(1000), Some(error)),
    }
}

impl ReplacementPolicy {
    /// Price the candidate against both fee and strict truncated-feerate rules.
    /// The absolute limit is independent of a mutable market target.
    pub fn fee(&self, target: u64, vsize: u64, limit: u64) -> Result<u64, PricingError> {
        if vsize == 0 || limit == 0 || self.conflicts.is_empty() {
            return Err(PricingError::InvalidEvidence);
        }
        let increment = rate_fee(self.incremental_sat_per_kvb, vsize)?;
        let mut fee = target.max(rate_fee(self.minimum_sat_per_kvb, vsize)?).max(
            self.evicted_fee
                .checked_add(increment)
                .ok_or(PricingError::Overflow)?,
        );
        for conflict in &self.conflicts {
            if conflict.vsize == 0 {
                return Err(PricingError::InvalidEvidence);
            }
            // CFeeRate comparison truncates each rate to integer sats/kvB.
            let old_rate = u128::from(conflict.modified_fee) * 1000 / u128::from(conflict.vsize);
            if self.evicted_fee < conflict.modified_fee {
                return Err(PricingError::InvalidEvidence);
            }
            let strict = (old_rate + 1)
                .checked_mul(u128::from(vsize))
                .ok_or(PricingError::Overflow)?;
            let strict =
                u64::try_from(strict.div_ceil(1000)).map_err(|_| PricingError::Overflow)?;
            fee = fee.max(strict);
        }
        if fee > limit {
            return Err(PricingError::Limit {
                required: fee,
                limit,
            });
        }
        Ok(fee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_observation_fallback_is_not_replacement_policy() {
        let ready =
            serde_json::json!({"loaded": true, "mempoolminfee": 0.00003, "minrelaytxfee": 0.00001});
        assert_eq!(fresh_rate(1300, Ok(&ready)), (3000, None));
        assert_eq!(fresh_rate(4000, Ok(&ready)), (4000, None));
        let loading = serde_json::json!({"loaded": false, "mempoolminfee": 0.0001});
        assert_eq!(
            fresh_rate(1300, Ok(&loading)),
            (1300, Some(PricingError::MempoolLoading))
        );
        assert_eq!(
            fresh_rate(100, Err(PricingError::RpcUnavailable)),
            (1000, Some(PricingError::RpcUnavailable))
        );
        let malformed = serde_json::json!({"loaded": true, "mempoolminfee": "bad"});
        assert_eq!(
            fresh_rate(1300, Ok(&malformed)),
            (1300, Some(PricingError::InvalidEvidence))
        );
    }

    fn policy(fee: u64, size: u64) -> ReplacementPolicy {
        ReplacementPolicy {
            minimum_sat_per_kvb: 1000,
            incremental_sat_per_kvb: 1000,
            evicted_fee: fee,
            conflicts: vec![Conflict {
                modified_fee: fee,
                vsize: size,
            }],
        }
    }

    #[test]
    fn observed_raise_and_same_target_retarget() {
        let p = policy(1110, 245);
        assert_eq!(p.fee(1480, 245, 3000), Ok(1480));
        assert_eq!(p.fee(1110, 245, 3000), Ok(1355));
        // A falling market target cannot lower the replacement safety allowance.
        assert_eq!(policy(1851, 245).fee(370, 245, 3000), Ok(2096));
    }

    #[test]
    fn strict_rate_can_bind_despite_same_inputs() {
        let p = policy(1851, 245);
        assert_eq!(p.fee(0, 300, 3000), Ok(2267));
    }

    #[test]
    fn descendants_modified_fees_and_relay_policy() {
        let mut p = policy(1110, 245);
        p.evicted_fee = 5110;
        assert_eq!(p.fee(1480, 245, 10000), Ok(5355));
        p.incremental_sat_per_kvb = 2501;
        assert_eq!(p.fee(1480, 245, 10000), Ok(5723));
        p.minimum_sat_per_kvb = 30000;
        assert_eq!(p.fee(1480, 245, 10000), Ok(7350));
    }

    #[test]
    fn exact_rounding_limits_and_invalid_data() {
        assert_eq!(rate_fee(1001, 245), Ok(246));
        assert!(matches!(
            policy(1110, 245).fee(1480, 245, 1479),
            Err(PricingError::Limit { .. })
        ));
        assert_eq!(
            policy(1110, 0).fee(1480, 245, 3000),
            Err(PricingError::InvalidEvidence)
        );
        assert_eq!(
            policy(u64::MAX, 245).fee(0, 245, u64::MAX),
            Err(PricingError::Overflow)
        );
        let mut p = policy(u64::MAX, 1);
        p.incremental_sat_per_kvb = 0;
        p.minimum_sat_per_kvb = 0;
        assert_eq!(p.fee(0, u64::MAX, u64::MAX), Err(PricingError::Overflow));
        let mut p = policy(1000, 245);
        p.evicted_fee = 1;
        assert_eq!(p.fee(0, 245, 3000), Err(PricingError::InvalidEvidence));
    }

    #[test]
    fn decimal_rpc_amounts_are_exact() {
        for (text, sats) in [
            ("0.00001000", 1000),
            ("0.00000001", 1),
            ("1.23456789", 123456789),
        ] {
            assert_eq!(
                bitcoin_amount(&serde_json::from_str(text).unwrap()),
                Ok(sats)
            );
        }
        for text in ["-0.1", "null", "\"0.1\"", "0.000000001"] {
            assert!(bitcoin_amount(&serde_json::from_str(text).unwrap()).is_err());
        }
    }

    #[test]
    fn scientific_rpc_amounts_are_exact() {
        // Real Bitcoin 25.1 mempool entries for low precise fees normalize this way.
        for (text, sats) in [
            ("3.51e-6", 351),
            ("1e-8", 1),
            ("1.3E-5", 1300),
            ("1e+1", 1_000_000_000),
            ("0.000000010", 1),
            ("184467440737.09551615", u64::MAX),
        ] {
            assert_eq!(
                bitcoin_amount(&serde_json::from_str(text).unwrap()),
                Ok(sats)
            );
        }
        for text in [
            "3.5100000000000004e-6",
            "1e-9",
            "1e100",
            "-1e-8",
            "184467440737.09551616",
        ] {
            assert!(bitcoin_amount(&serde_json::from_str(text).unwrap()).is_err());
        }
    }
}
