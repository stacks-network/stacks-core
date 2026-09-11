;; Core of an upgradable signer manager for pox-5.
;;
;; This contract is the signer's identity with pox-5 (the principal passed to
;; `register-signer`) and the vault for the sBTC it earns. It holds the stable
;; per-staker state and enforces the invariants around it, but has no user
;; facing policy of its own. All policy, including governance, lives in a
;; separate module contract that stakers and operators call directly.

(impl-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)
(use-trait signer-manager-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)

;; A pox-5 callback (validate-stake!) was invoked by a
;; principal other than the pox-5 contract.
(define-constant ERR_UNAUTHORIZED_CALLER (err u1001))
;; A module function was invoked by a principal other than the current module.
(define-constant ERR_UNAUTHORIZED_MODULE (err u1002))
;; The calldata provided when staking was invalid
(define-constant ERR_INVALID_CALLDATA (err u1003))
;; The pox-addr provided isn't a valid sBTC withdrawal recipient
(define-constant ERR_INVALID_POX_ADDR (err u1004))
;; A staker tried to settle rewards, but they had none available
(define-constant ERR_NO_CLAIMABLE_REWARDS (err u1005))
;; The amount exceeds the staker's pending payout balance
(define-constant ERR_INSUFFICIENT_PENDING (err u1006))
;; A third party tried to pay out less than the staker's `min-claim`
(define-constant ERR_BELOW_MIN_CLAIM (err u1007))
;; An L1 payout would not clear `max-fee` plus the sBTC dust limit
(define-constant ERR_BELOW_DUST_LIMIT (err u1008))
;; Attempted to withdraw more fees than have accrued.
(define-constant ERR_INSUFFICIENT_FEES (err u1009))
;; The given withdrawal-request id is not tracked by this contract.
(define-constant ERR_UNKNOWN_WITHDRAWAL_REQUEST (err u1010))
;; The withdrawal request has not been rejected, so its full
;; `amount + max-fee` is not reclaimable for the staker.
(define-constant ERR_WITHDRAWAL_NOT_REJECTED (err u1011))
;; The withdrawal request has not been accepted, so it cannot be
;; settled via `settle-accepted-withdrawal`.
(define-constant ERR_WITHDRAWAL_NOT_ACCEPTED (err u1012))
;; No refunds available to sweep.
(define-constant ERR_NO_REFUNDS (err u1013))
;; `set-module` was given a principal that is not a deployed contract.
(define-constant ERR_INVALID_MODULE (err u1014))

;; sBTC rejects withdrawals of `DUST_LIMIT` sats or less (`sbtc-withdrawal`).
(define-constant DUST_LIMIT u546)

;; The module contract allowed to drive this contract's privileged functions.
(define-data-var current-module principal tx-sender)

;; How each staker wants rewards paid out. `min-claim` is the smallest payout
;; a third party may trigger on the staker's behalf.
(define-map payout-configs
    principal
    {
        l1-withdrawal: (optional {
            pox-addr: {
                version: (buff 1),
                hashbytes: (buff 32),
            },
            max-fee: uint,
            min-claim: uint,
        }),
        sbtc-recipient: (optional principal),
    }
)

;; sBTC settled for a staker but not yet paid out. Credited by
;; `settle-staker-rewards` and by reclaiming a rejected L1 withdrawal,
;; debited by `charge-fee` and `payout`.
(define-map pending-payouts
    principal
    uint
)
(define-data-var total-pending uint u0)

;; sBTC pulled in by `claim-rewards` that no staker has settled yet, per
;; `(reward-cycle, bond-index)` so one cycle's settlements can never draw on
;; another's. Every settlement debits its bucket by the staker's gross.
(define-map reward-reserves
    {
        reward-cycle: uint,
        bond-index: (optional uint),
    }
    uint
)
(define-data-var total-reserved uint u0)

;; Fees charged by the module, withdrawable via `withdraw-fees`.
(define-data-var earned-fees uint u0)

;; Withdrawal request ID -> the staker whose payout created it.
(define-map withdrawal-requests
    uint
    principal
)

;; Sum of `amount + max-fee` over every live entry in `withdrawal-requests`.
;; That sBTC has either left for the sBTC withdrawal system (pending) or come
;; back (rejected) without being credited yet, so it stays owed to stakers.
(define-data-var withdrawal-liability uint u0)

;; Callback function from a `stake` transaction.
;;
;; If `signer-calldata` is provided, it must decode to a payout config, which
;; is saved for the staker. Without calldata the staker's existing config (if
;; any) is left untouched; use the module's `clear-payout-config` to remove it.
(define-public (validate-stake!
        (staker principal)
        ;; #[allow(unused_binding)]
        (first-index uint)
        ;; #[allow(unused_binding)]
        (num-indexes uint)
        ;; #[allow(unused_binding)]
        (amount-ustx uint)
        ;; #[allow(unused_binding)]
        (amount-sats uint)
        ;; #[allow(unused_binding)]
        (is-bond bool)
        (signer-calldata (optional (buff 500)))
    )
    (begin
        (try! (authorize-pox-5))
        (match signer-calldata
            calldata (let ((config (try! (parse-payout-config calldata))))
                (try! (check-payout-config config))
                (ok (map-set payout-configs staker config))
            )
            (ok true)
        )
    )
)

;;; Module functions

;; Store a payout config for `staker`.
(define-public (set-payout-config
        (staker principal)
        (config {
            l1-withdrawal: (optional {
                pox-addr: {
                    version: (buff 1),
                    hashbytes: (buff 32),
                },
                max-fee: uint,
                min-claim: uint,
            }),
            sbtc-recipient: (optional principal),
        })
    )
    (begin
        (try! (authorize-module))
        (try! (check-payout-config config))
        (print {
            topic: "set-payout-config",
            staker: staker,
            config: config,
        })
        (ok (map-set payout-configs staker config))
    )
)

;; Remove `staker`'s payout config so rewards are paid to them as sBTC.
(define-public (clear-payout-config (staker principal))
    (begin
        (try! (authorize-module))
        (print {
            topic: "clear-payout-config",
            staker: staker,
        })
        (ok (map-delete payout-configs staker))
    )
)

;; Pull this signer's rewards for `reward-cycle` out of pox-5 and reserve
;; them for its stakers.
(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (begin
        (try! (authorize-module))
        (let ((result (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 claim-rewards
                bond-periods reward-cycle
            ))))
            (reserve-rewards reward-cycle none
                (get earned (get stx-rewards result))
            )
            (fold reserve-bond-rewards (get bond-rewards result) reward-cycle)
            (ok result)
        )
    )
)

;; Settle `staker`'s rewards for one `(reward-cycle, bond-index)` with pox-5
;; and credit the gross amount to their pending payout. Returns the gross.
(define-public (settle-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (begin
        (try! (authorize-module))
        (let (
                (key {
                    reward-cycle: reward-cycle,
                    bond-index: bond-index,
                })
                ;; `unwrap-panic` is ok here: there is no `err` type returnable
                (gross (get earned
                    (unwrap-panic (contract-call? 'ST000000000000000000002AMW42H.pox-5
                        claim-staker-rewards-for-signer staker reward-cycle
                        bond-index
                    ))
                ))
                (reserve (default-to u0 (map-get? reward-reserves key)))
            )
            (asserts! (> gross u0) ERR_NO_CLAIMABLE_REWARDS)
            (asserts! (>= reserve gross) ERR_NO_CLAIMABLE_REWARDS)
            (map-set reward-reserves key (- reserve gross))
            (var-set total-reserved (- (var-get total-reserved) gross))
            (credit-pending staker gross)
            (print {
                topic: "settle-staker-rewards",
                staker: staker,
                reward-cycle: reward-cycle,
                bond-index: bond-index,
                amount-sats: gross,
            })
            (ok gross)
        )
    )
)

;; Move `amount` of `staker`'s pending payout into the signer's earned fees.
(define-public (charge-fee
        (staker principal)
        (amount uint)
    )
    (begin
        (try! (authorize-module))
        (try! (debit-pending staker amount))
        (var-set earned-fees (+ (var-get earned-fees) amount))
        (print {
            topic: "charge-fee",
            staker: staker,
            amount-sats: amount,
        })
        (ok amount)
    )
)

;; Pay `amount` of `staker`'s pending payout to their configured destination:
;; an sBTC withdrawal to their L1 address, or an sBTC transfer to their
;; `sbtc-recipient` (or themselves). Anyone but the staker must clear their
;; `min-claim`. Returns the withdrawal request id when routed to L1.
(define-public (payout
        (staker principal)
        (amount uint)
    )
    (let ((config (default-to {
            l1-withdrawal: none,
            sbtc-recipient: none,
        }
            (map-get? payout-configs staker)
        )))
        (try! (authorize-module))
        (try! (debit-pending staker amount))
        (let ((withdrawal-request (match (get l1-withdrawal config)
                l1 (some (try! (initiate-withdrawal staker amount l1)))
                (begin
                    (try! (transfer-sbtc amount
                        (default-to staker (get sbtc-recipient config))
                    ))
                    none
                )
            )))
            (print {
                topic: "payout",
                staker: staker,
                amount-sats: amount,
                withdrawal-request: withdrawal-request,
            })
            (ok withdrawal-request)
        )
    )
)

;; Credit a REJECTED L1 withdrawal's full `amount + max-fee` back to the
;; staker's pending payout, so their next `payout` retries it.
(define-public (reclaim-failed-withdrawal (request-id uint))
    (begin
        (try! (authorize-module))
        (let (
                (staker (unwrap! (map-get? withdrawal-requests request-id)
                    ERR_UNKNOWN_WITHDRAWAL_REQUEST
                ))
                (request (unwrap!
                    (contract-call?
                        'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry
                        get-withdrawal-request request-id
                    )
                    ERR_UNKNOWN_WITHDRAWAL_REQUEST
                ))
                (refund (+ (get amount request) (get max-fee request)))
            )
            ;; `status` is `none` while pending and `(some true)` once accepted;
            ;; only `(some false)` (rejected) unlocks the full amount back here.
            (asserts! (is-eq (get status request) (some false))
                ERR_WITHDRAWAL_NOT_REJECTED
            )
            (map-delete withdrawal-requests request-id)
            (var-set withdrawal-liability
                (- (var-get withdrawal-liability) refund)
            )
            (credit-pending staker refund)
            (print {
                topic: "reclaim-failed-withdrawal",
                request-id: request-id,
                staker: staker,
                amount-sats: refund,
            })
            (ok refund)
        )
    )
)

;; Retire an ACCEPTED L1 withdrawal. The staker was paid on L1 and only the
;; unused fee budget came back as dust, which this makes sweepable.
(define-public (settle-accepted-withdrawal (request-id uint))
    (begin
        (try! (authorize-module))
        (let (
                (staker (unwrap! (map-get? withdrawal-requests request-id)
                    ERR_UNKNOWN_WITHDRAWAL_REQUEST
                ))
                (request (unwrap!
                    (contract-call?
                        'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry
                        get-withdrawal-request request-id
                    )
                    ERR_UNKNOWN_WITHDRAWAL_REQUEST
                ))
                (liability (+ (get amount request) (get max-fee request)))
            )
            (asserts! (is-eq (get status request) (some true))
                ERR_WITHDRAWAL_NOT_ACCEPTED
            )
            (map-delete withdrawal-requests request-id)
            (var-set withdrawal-liability
                (- (var-get withdrawal-liability) liability)
            )
            (print {
                topic: "settle-accepted-withdrawal",
                request-id: request-id,
                staker: staker,
                liability-released: liability,
            })
            (ok true)
        )
    )
)

;; Withdraw earned fees.
(define-public (withdraw-fees
        (amount uint)
        (recipient principal)
    )
    (let ((fees (var-get earned-fees)))
        (try! (authorize-module))
        (asserts! (<= amount fees) ERR_INSUFFICIENT_FEES)
        (var-set earned-fees (- fees amount))
        (try! (transfer-sbtc amount recipient))
        (ok amount)
    )
)

;; Sweep sBTC that is owed to nobody: the balance net of earned fees,
;; unsettled reserves, pending payouts and live withdrawal liability. In
;; practice this is the unused fee budget minted back by accepted L1
;; withdrawals.
(define-public (sweep-fee-refunds (recipient principal))
    (let (
            (balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
            (reserved (get-reserved-balance))
            (sweepable (if (>= balance reserved)
                (- balance reserved)
                u0
            ))
        )
        (try! (authorize-module))
        (asserts! (> sweepable u0) ERR_NO_REFUNDS)
        (print {
            topic: "sweep-fee-refunds",
            amount-sats: sweepable,
            recipient: recipient,
        })
        (try! (transfer-sbtc sweepable recipient))
        (ok sweepable)
    )
)

;; Hand control of this contract to a new module. The module must be a
;; deployed contract: nothing but the current module can ever call this, so
;; a typo here would strand the vault.
(define-public (set-module (module principal))
    (begin
        (try! (authorize-module))
        (asserts! (is-ok (contract-hash? module)) ERR_INVALID_MODULE)
        (print {
            topic: "set-module",
            old-module: (var-get current-module),
            new-module: module,
        })
        (var-set current-module module)
        (ok module)
    )
)

;; Register this contract with a specific signer key. The signer key grant
;; must not have been used yet.
(define-public (register-self
        (signer-manager <signer-manager-trait>)
        (signer-key (buff 33))
        (auth-id uint)
        (signer-sig (buff 65))
    )
    (begin
        (try! (authorize-module))
        (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 grant-signer-key
            signer-key current-contract auth-id signer-sig
        ))
        (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-signer
            signer-manager signer-key
        )
    )
)

(define-private (authorize-module)
    (ok (asserts! (is-eq contract-caller (var-get current-module))
        ERR_UNAUTHORIZED_MODULE
    ))
)

;; Ensure that the immediate caller is the pox-5 contract. The trait callbacks
;; (validate-stake!) write per-staker state keyed by the
;; `staker` argument; they must only ever be driven by pox-5, never invoked
;; directly by an external principal.
(define-private (authorize-pox-5)
    (ok (asserts! (is-eq contract-caller 'ST000000000000000000002AMW42H.pox-5)
        ERR_UNAUTHORIZED_CALLER
    ))
)

(define-private (reserve-rewards
        (reward-cycle uint)
        (bond-index (optional uint))
        (amount uint)
    )
    (let ((key {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
        }))
        (map-set reward-reserves key
            (+ (default-to u0 (map-get? reward-reserves key)) amount)
        )
        (var-set total-reserved (+ (var-get total-reserved) amount))
    )
)

(define-private (reserve-bond-rewards
        (bond-info {
            bond-index: uint,
            earned: uint,
            rewards-per-token: uint,
        })
        (reward-cycle uint)
    )
    (begin
        (reserve-rewards reward-cycle (some (get bond-index bond-info))
            (get earned bond-info)
        )
        reward-cycle
    )
)

(define-private (credit-pending
        (staker principal)
        (amount uint)
    )
    (begin
        (map-set pending-payouts staker (+ (get-pending-payout staker) amount))
        (var-set total-pending (+ (var-get total-pending) amount))
    )
)

(define-private (debit-pending
        (staker principal)
        (amount uint)
    )
    (let ((pending (get-pending-payout staker)))
        (asserts! (and (> amount u0) (<= amount pending))
            ERR_INSUFFICIENT_PENDING
        )
        (map-set pending-payouts staker (- pending amount))
        (ok (var-set total-pending (- (var-get total-pending) amount)))
    )
)

;; Withdraw `amount - max-fee` to the staker's L1 address with this contract
;; as the requester, and record the request so its outcome can be settled.
(define-private (initiate-withdrawal
        (staker principal)
        (amount uint)
        (l1 {
            pox-addr: {
                version: (buff 1),
                hashbytes: (buff 32),
            },
            max-fee: uint,
            min-claim: uint,
        })
    )
    (let ((max-fee (get max-fee l1)))
        (asserts! (> amount (+ max-fee DUST_LIMIT)) ERR_BELOW_DUST_LIMIT)
        (asserts! (or (is-eq tx-sender staker) (>= amount (get min-claim l1)))
            ERR_BELOW_MIN_CLAIM
        )
        (let ((request-id (try! (as-contract?
                ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                    "sbtc-token" amount
                ))
                (try! (contract-call?
                    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal
                    initiate-withdrawal-request (- amount max-fee)
                    (get pox-addr l1) max-fee
                ))
            ))))
            (map-set withdrawal-requests request-id staker)
            (var-set withdrawal-liability
                (+ (var-get withdrawal-liability) amount)
            )
            (ok request-id)
        )
    )
)

(define-private (transfer-sbtc
        (amount uint)
        (recipient principal)
    )
    (as-contract?
        ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
            "sbtc-token" amount
        ))
        (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
            transfer amount tx-sender recipient none
        ))
    )
)

;; Decode a payout config from calldata.
(define-read-only (parse-payout-config (calldata (buff 500)))
    (ok (unwrap!
        (from-consensus-buff? {
            l1-withdrawal: (optional {
                pox-addr: {
                    version: (buff 1),
                    hashbytes: (buff 32),
                },
                max-fee: uint,
                min-claim: uint,
            }),
            sbtc-recipient: (optional principal),
        }
            calldata
        )
        ERR_INVALID_CALLDATA
    ))
)

;; Delegate to the sBTC withdrawal contract so the accepted recipient
;; shapes can't drift from what `initiate-withdrawal-request` allows.
(define-read-only (check-payout-config (config {
    l1-withdrawal: (optional {
        pox-addr: {
            version: (buff 1),
            hashbytes: (buff 32),
        },
        max-fee: uint,
        min-claim: uint,
    }),
    sbtc-recipient: (optional principal),
}))
    (match (get l1-withdrawal config)
        l1 (ok (asserts!
            (is-ok (contract-call?
                'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal
                validate-recipient (get pox-addr l1)
            ))
            ERR_INVALID_POX_ADDR
        ))
        (ok true)
    )
)

(define-read-only (get-current-module)
    (var-get current-module)
)

(define-read-only (get-payout-config (staker principal))
    (map-get? payout-configs staker)
)

(define-read-only (get-pending-payout (staker principal))
    (default-to u0 (map-get? pending-payouts staker))
)

(define-read-only (get-reward-reserve
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (default-to u0
        (map-get? reward-reserves {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
        })
    )
)

(define-read-only (get-earned-fees)
    (var-get earned-fees)
)

(define-read-only (get-withdrawal-liability)
    (var-get withdrawal-liability)
)

(define-read-only (get-withdrawal-request-staker (request-id uint))
    (map-get? withdrawal-requests request-id)
)

;; sBTC in this contract that is spoken for.
(define-read-only (get-reserved-balance)
    (+ (var-get earned-fees) (var-get total-reserved) (var-get total-pending)
        (var-get withdrawal-liability)
    )
)
