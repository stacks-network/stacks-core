;; Signer manager module, v1.
;;
;; This is the contract stakers and operators interact with. It holds the
;; signer's policies and governance and drives `signer-manager-core`, which is
;; the signer's identity with pox-5 and the vault for its sBTC.
;;
;; This module can only interact with core while this contract is set as the
;; current module. Upgrading the module is handled by calling `set-module` on core from
;; this contract.

(use-trait signer-manager-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)

;; Staker functions must be called directly by the staker.
(define-constant ERR_UNAUTHORIZED_CALLER (err u2001))
;; Attempted to call an admin function
(define-constant ERR_UNAUTHORIZED_ADMIN (err u2002))
;; The fees provided when updating fees is invalid
(define-constant ERR_INVALID_FEES_BIPS (err u2003))
;; The given withdrawal-request id is not tracked by core.
(define-constant ERR_UNKNOWN_WITHDRAWAL_REQUEST (err u2004))

(define-constant MAX_BIPS u10000)

(define-map admins
    principal
    bool
)
(map-set admins tx-sender true)

;; Fees taken, in basis points, from rewards. The rate is snapshotted per
;; `(reward-cycle, bond-index)` when `claim-rewards` pulls that cycle in, so
;; later fee changes never touch rewards already pulled from pox-5.
(define-data-var fees-bips uint u0)
(define-map fee-bips-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
    }
    uint
)

;;; Rewards

;; Pull this signer's rewards for `reward-cycle` into core. Callable by
;; anyone; must happen before stakers can settle that cycle.
(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (let ((result (try! (contract-call? .signer-manager-core claim-rewards bond-periods
            reward-cycle
        ))))
        (map-insert fee-bips-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: none,
        }
            (var-get fees-bips)
        )
        (fold snapshot-bond-fee (get bond-rewards result) reward-cycle)
        (ok result)
    )
)

;; Settle a staker's rewards for one `(reward-cycle, bond-index)` into their
;; pending payout, charging the fee snapshotted for that cycle. Callable by
;; anyone. Returns `{ gross, fee }`.
(define-public (settle-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (gross (try! (contract-call? .signer-manager-core settle-staker-rewards staker
                reward-cycle bond-index
            )))
            (fee (/ (* gross (get-fee-bips-for-cycle reward-cycle bond-index))
                MAX_BIPS
            ))
        )
        (if (> fee u0)
            (try! (contract-call? .signer-manager-core charge-fee staker fee))
            u0
        )
        (ok {
            gross: gross,
            fee: fee,
        })
    )
)

;; Pay out a staker's whole pending balance to their configured destination.
;; Callable by anyone, but third parties must clear the staker's `min-claim`.
;; Returns `{ amount, withdrawal-request }`.
(define-public (payout (staker principal))
    (let ((amount (contract-call? .signer-manager-core get-pending-payout staker)))
        (ok {
            amount: amount,
            withdrawal-request: (try! (contract-call? .signer-manager-core payout staker amount)),
        })
    )
)

;; Settle one `(reward-cycle, bond-index)` and pay out in a single call.
;; Returns `{ earned, withdrawal-request }` where `earned` is the whole
;; pending balance paid, including anything settled earlier.
(define-public (claim-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (begin
        (try! (settle-staker-rewards staker reward-cycle bond-index))
        (let ((paid (try! (payout staker))))
            (ok {
                earned: (get amount paid),
                withdrawal-request: (get withdrawal-request paid),
            })
        )
    )
)

;;; L1 withdrawal outcomes

;; Credit a REJECTED L1 withdrawal back to the staker's pending payout.
(define-public (reclaim-failed-withdrawal (request-id uint))
    (contract-call? .signer-manager-core reclaim-failed-withdrawal request-id)
)

;; Reclaim a REJECTED L1 withdrawal and immediately pay out again using the
;; staker's current payout config.
(define-public (retry-failed-withdrawal (request-id uint))
    (let ((staker (unwrap!
            (contract-call? .signer-manager-core get-withdrawal-request-staker
                request-id
            )
            ERR_UNKNOWN_WITHDRAWAL_REQUEST
        )))
        (try! (reclaim-failed-withdrawal request-id))
        (payout staker)
    )
)

;; Retire an ACCEPTED L1 withdrawal so its unused fee budget is sweepable.
(define-public (settle-accepted-withdrawal (request-id uint))
    (contract-call? .signer-manager-core settle-accepted-withdrawal request-id)
)

;;; Staker functions

;; Set your own payout config. With `l1-withdrawal` set, rewards are withdrawn
;; to BTC at `pox-addr` with an sBTC withdrawal fee budget of `max-fee`, and
;; a minimum withdrawal amount of `min-claim`.
;; Otherwise they are paid as sBTC to `sbtc-recipient`, or to you if none.
(define-public (set-payout-config
        (l1-withdrawal (optional {
            pox-addr: {
                version: (buff 1),
                hashbytes: (buff 32),
            },
            max-fee: uint,
            min-claim: uint,
        }))
        (sbtc-recipient (optional principal))
    )
    (begin
        (try! (authorize-staker))
        (contract-call? .signer-manager-core set-payout-config tx-sender {
            l1-withdrawal: l1-withdrawal,
            sbtc-recipient: sbtc-recipient,
        })
    )
)

;; Remove your payout config so rewards are paid to you as sBTC.
(define-public (clear-payout-config)
    (begin
        (try! (authorize-staker))
        (contract-call? .signer-manager-core clear-payout-config tx-sender)
    )
)

;;; Admin functions

;; Update the allowed admin principal
(define-public (update-admin
        (admin principal)
        (enabled bool)
    )
    (begin
        (try! (authorize-admin))
        (print {
            topic: "update-admin",
            admin: admin,
            enabled: enabled,
        })
        (map-set admins admin enabled)
        (ok admin)
    )
)

;; Update the fees taken from rewards
(define-public (update-fees (new-fees uint))
    (begin
        (try! (authorize-admin))
        (asserts! (< new-fees MAX_BIPS) ERR_INVALID_FEES_BIPS)
        (print {
            topic: "update-fees",
            old-fees: (var-get fees-bips),
            new-fees: new-fees,
        })
        (var-set fees-bips new-fees)
        (ok true)
    )
)

;; Withdraw accrued fees from staker rewards.
(define-public (withdraw-fees
        (amount uint)
        (recipient principal)
    )
    (begin
        (try! (authorize-admin))
        (contract-call? .signer-manager-core withdraw-fees amount recipient)
    )
)

;; Sweep sBTC owed to nobody (unused L1 fee budgets) to a recipient.
(define-public (sweep-fee-refunds (recipient principal))
    (begin
        (try! (authorize-admin))
        (contract-call? .signer-manager-core sweep-fee-refunds recipient)
    )
)

;; Upgrade: hand control of core to a new module. This contract stops
;; working once core no longer recognizes it.
(define-public (set-module (module principal))
    (begin
        (try! (authorize-admin))
        (contract-call? .signer-manager-core set-module module)
    )
)

;; Register core with pox-5 under a specific signer key. The signer key grant
;; must not have been used yet.
(define-public (register-self
        (signer-manager <signer-manager-trait>)
        (signer-key (buff 33))
        (auth-id uint)
        (signer-sig (buff 65))
    )
    (begin
        (try! (authorize-admin))
        (contract-call? .signer-manager-core register-self signer-manager
            signer-key auth-id signer-sig
        )
    )
)

(define-private (authorize-staker)
    (ok (asserts! (is-eq contract-caller tx-sender) ERR_UNAUTHORIZED_CALLER))
)

;; Admins are checked on `contract-caller` so a contract (multisig, DAO) can
;; be an admin, while a non-admin contract can never act for an admin wallet.
(define-private (authorize-admin)
    (ok (asserts! (is-admin contract-caller) ERR_UNAUTHORIZED_ADMIN))
)

(define-private (snapshot-bond-fee
        (bond-info {
            bond-index: uint,
            earned: uint,
            rewards-per-token: uint,
        })
        (reward-cycle uint)
    )
    (begin
        (map-insert fee-bips-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: (some (get bond-index bond-info)),
        }
            (var-get fees-bips)
        )
        reward-cycle
    )
)

(define-read-only (get-fees-bips)
    (var-get fees-bips)
)

(define-read-only (get-fee-bips-for-cycle
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (default-to u0
        (map-get? fee-bips-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
        })
    )
)

(define-read-only (is-admin (caller principal))
    (default-to false (map-get? admins caller))
)

(define-read-only (get-payout-config (staker principal))
    (contract-call? .signer-manager-core get-payout-config staker)
)
