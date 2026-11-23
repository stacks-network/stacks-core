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

//! Status codes (ABI 6.2).
//!
//! A host function with a `status` result returns [`SUCCESS`] or one of the
//! codes listed with it. Each such function, or group of functions with the
//! same codes, has its own type here, because a code's meaning belongs to the
//! function: `1` is "amount is zero" from `ft_mint` and "insufficient
//! balance" from `ft_transfer`.
//!
//! The table of host functions ([`crate::host`]) gives each function the
//! codes of its type.

/// The status every function returns for success.
pub const SUCCESS: i32 = 0;

macro_rules! status_codes {
    ($($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident = $code:literal,)+ })*) => {
        $(
            $(#[$doc])*
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            #[repr(i32)]
            pub enum $name {
                $($(#[$vdoc])* $variant = $code,)+
            }

            impl $name {
                /// Every code of the function.
                pub const ALL: &[$name] = &[$($name::$variant,)+];

                /// Every code of the function, in increasing order.
                pub const CODES: &[i32] = &[$($code,)+];

                /// The code, as the host function returns it.
                pub const fn code(self) -> i32 {
                    self as i32
                }

                /// The status with the given code. [`SUCCESS`] is not one.
                pub const fn from_code(code: i32) -> Option<$name> {
                    match code {
                        $($code => Some($name::$variant),)+
                        _ => None,
                    }
                }
            }

            impl From<$name> for i32 {
                fn from(status: $name) -> i32 {
                    status.code()
                }
            }
        )*
    };
}

status_codes! {
    /// Status of the block-data lookups that return a `status`, other than
    /// `tenure_block_reward`: `stacks_block_id_header_hash`,
    /// `stacks_block_header_hash`, `stacks_block_time`,
    /// `tenure_burnchain_header_hash`, `tenure_time`, `tenure_vrf_seed`,
    /// `tenure_miner_spend_total`, `tenure_miner_spend_winner`,
    /// `burn_block_header_hash`, and `burn_block_pox_payout`.
    BlockLookupStatus {
        /// The host does not serve the height.
        NotServed = 1,
    }

    /// Status of `tenure_block_reward`.
    BlockRewardStatus {
        /// The host does not serve the height.
        NotServed = 1,
        /// The reward has not matured.
        NotMatured = 2,
    }

    /// Status of `ft_mint`.
    FtMintStatus {
        /// The amount is zero.
        ZeroAmount = 1,
    }

    /// Status of `ft_burn`.
    FtBurnStatus {
        /// The balance is insufficient, or the amount is zero.
        InsufficientBalanceOrZeroAmount = 1,
    }

    /// Status of `ft_transfer`.
    FtTransferStatus {
        /// The balance is insufficient.
        InsufficientBalance = 1,
        /// `from` is `to`.
        SameParty = 2,
        /// The amount is zero.
        ZeroAmount = 3,
    }

    /// Status of `nft_mint`.
    NftMintStatus {
        /// The identifier already exists.
        AlreadyExists = 1,
    }

    /// Status of `nft_burn`.
    NftBurnStatus {
        /// `from` does not own the identifier.
        NotOwner = 1,
        /// The identifier does not exist.
        NotFound = 3,
    }

    /// Status of `nft_transfer`.
    NftTransferStatus {
        /// `from` does not own the identifier.
        NotOwner = 1,
        /// `from` is `to`.
        SameParty = 2,
        /// The identifier does not exist.
        NotFound = 3,
    }

    /// Status of `stx_transfer`.
    StxTransferStatus {
        /// The balance is insufficient.
        InsufficientBalance = 1,
        /// `from` is `to`.
        SameParty = 2,
        /// The amount is zero.
        ZeroAmount = 3,
        /// `from` is not the frame's `sender`.
        NotSender = 4,
    }

    /// Status of `stx_burn`.
    StxBurnStatus {
        /// The balance is insufficient.
        InsufficientBalance = 1,
        /// The amount is zero.
        ZeroAmount = 3,
        /// `from` is not the frame's `sender`.
        NotSender = 4,
    }

    /// Status of `contract_hash`.
    ContractHashStatus {
        /// The principal is a standard principal.
        StandardPrincipal = 1,
        /// No such contract.
        NoSuchContract = 2,
    }

    /// Status of `secp256k1_recover`.
    Secp256k1RecoverStatus {
        /// The signature is malformed or not canonical.
        BadSignature = 1,
        /// Recovery failed.
        RecoveryFailed = 2,
    }

    /// Status of `secp256k1_decompress`.
    Secp256k1DecompressStatus {
        /// The key is not valid.
        InvalidKey = 1,
    }
}
