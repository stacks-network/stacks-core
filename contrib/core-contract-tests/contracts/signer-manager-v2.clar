;; Reference implementation for the signer manager trait, to be used with pox-5.
;;
;; v2 of `signer-manager.clar`. Same shape as v1 -- stakers may register an L1
;; `pox-addr` so their rewards are paid out over sBTC withdrawals, and admins
;; may take a bips fee from rewards -- with the following changes:
;;
;;   * Unused sBTC withdrawal fee budget (`max-fee - actual-fee`) is credited
;;     back to the staker who earned it instead of pooling for an admin sweep.
;;   * Stakers set a `min-claim` floor; only the staker may trigger a claim
;;     below it, so a third party cannot burn their reward on L1 fees.
;;   * Fee increases are queued and only take effect `FEE_ACTIVATION_DELAY_CYCLES`
;;     reward cycles later, giving stakers time to leave. Decreases are immediate.
;;   * L1 payouts are checked against the sBTC dust limit up front, so a claim
;;     that cannot succeed fails with a legible error instead of an opaque
;;     `(err u502)` from the sBTC contracts.
;;   * Stakers can set/clear their payout config directly here, without having
;;     to re-drive `stake` / `stake-update` on pox-5.
;;   * Unclaimed rewards are tracked per `(reward-cycle, bond-index)` rather
;;     than as one global counter, so a claim against one cycle can never be
;;     funded out of another cycle's reserve.
;;   * The last admin cannot be removed.
;;
;; Fees are still snapshotted per cycle when `claim-rewards` crystallizes it,
;; so a rate change never applies to a cycle that has already been pulled.

(impl-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)
(use-trait signer-manager-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)

;; A staker tried to claim rewards, but they had none available
(define-constant ERR_NO_CLAIMABLE_REWARDS (err u1001))
;; Attempted to call an admin function
(define-constant ERR_UNAUTHORIZED_ADMIN (err u1002))
;; the calldata provided when staking was invalid
(define-constant ERR_INVALID_CALLDATA (err u1003))
;; The pox-addr provided as calldata isn't valid
(define-constant ERR_INVALID_POX_ADDR (err u1004))
;; The fees provided when updating fees is invalid
(define-constant ERR_INVALID_FEES_BIPS (err u1005))
;; A pox-5 callback (validate-stake!) was invoked by a
;; principal other than the pox-5 contract.
(define-constant ERR_UNAUTHORIZED_CALLER (err u1006))
;; Attempted to withdraw more fees than have accrued.
(define-constant ERR_INSUFFICIENT_FEES (err u1007))
;; The given withdrawal-request id is not tracked by this contract.
(define-constant ERR_UNKNOWN_WITHDRAWAL_REQUEST (err u1008))
;; The withdrawal request has not been rejected, so its full
;; `amount + max-fee` is not reclaimable for the staker.
(define-constant ERR_WITHDRAWAL_NOT_REJECTED (err u1009))
;; No refunds available to sweep.
(define-constant ERR_NO_REFUNDS (err u1010))
;; The withdrawal request has not been accepted, so it cannot be
;; settled via `settle-accepted-withdrawal`.
(define-constant ERR_WITHDRAWAL_NOT_ACCEPTED (err u1011))
;; The L1 payout after `max-fee` would be at or below the sBTC dust
;; limit, so `initiate-withdrawal-request` cannot succeed. Let rewards
;; accrue further, or clear the payout config to be paid in sBTC.
(define-constant ERR_BELOW_DUST_LIMIT (err u1012))
;; A third party tried to claim rewards for a staker whose L1 payout
;; would be below the `min-claim` floor that staker set.
(define-constant ERR_BELOW_MIN_CLAIM (err u1013))
;; `min-claim` must leave a spendable (non-dust) output after `max-fee`.
(define-constant ERR_INVALID_MIN_CLAIM (err u1014))
;; Refusing to remove the only remaining admin.
(define-constant ERR_LAST_ADMIN (err u1015))
;; `register-self` was passed a signer-manager other than this contract.
(define-constant ERR_NOT_SELF (err u1016))
;; The staker has no fee refund credited.
(define-constant ERR_NO_REFUND_CREDIT (err u1019))

;; Highest fee an admin may set, in basis points. Inclusive: `u500` is
;; exactly 5%, and 5% is settable.
(define-constant MAX_FEE_BIPS u500)
(define-constant BIPS_DENOMINATOR u10000)

;; A fee *increase* only becomes snapshottable this many reward cycles after
;; it is queued, so stakers can unstake before it applies to them. Decreases
;; apply immediately.
(define-constant FEE_ACTIVATION_DELAY_CYCLES u2)

;; Mirrors `DUST_LIMIT` in `.sbtc-withdrawal`. `initiate-withdrawal-request`
;; asserts `(> amount DUST_LIMIT)`; we check the same bound before calling in
;; so the failure is attributable to this contract.
(define-constant DUST_LIMIT u546)

;; default to allowing deployer to register as a pool
(define-map admins
    principal
    bool
)
(map-set admins tx-sender true)

;; Number of principals currently mapped to `true` in `admins`. Tracked so
;; `update-admin` can refuse to remove the last one, which would permanently
;; brick every admin-gated function.
(define-data-var admin-count uint u1)

;; Fees taken, in basis points, from rewards. This is the rate in force now;
;; `pending-fees-bips` / `pending-fees-cycle` hold a queued change. Read
;; `get-active-fee-bips` rather than either var directly.
(define-data-var fees-bips uint u0)
(define-data-var pending-fees-bips uint u0)
;; The reward cycle at which `pending-fees-bips` becomes the active rate.
(define-data-var pending-fees-cycle uint u0)

;; Amount of earned fees that are held by the contract.
;; When fees are transferred out of the contract, this value
;; must be deducted.
(define-data-var earned-fees uint u0)

(define-map fee-bips-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
    }
    uint
)

;; When stakers provide L1 withdrawal info -- as pox-5 calldata, or directly
;; via `set-payout-config` -- it is stored here.
;;
;; `min-claim` is the smallest net reward for which a *third party* may trigger
;; an L1 payout on the staker's behalf. Without it, anyone can force a
;; withdrawal the moment any reward is claimable, burning up to `max-fee` in
;; BTC fees on a trivial amount. The staker themselves is never gated by it.
(define-map payout-configs
    principal
    {
        pox-addr: {
            version: (buff 1),
            hashbytes: (buff 32),
        },
        max-fee: uint,
        min-claim: uint,
    }
)

;; Mapping of a given withdrawal request ID to the staker
;; whose rewards created that withdrawal.
(define-map withdrawal-requests
    uint
    principal
)

;; Sum of `amount + max-fee` over every live (un-settled) entry in
;; `withdrawal-requests`. Incremented when a withdrawal is initiated in
;; `claim-staker-rewards` and decremented when the request is settled
;; (`reclaim-failed-withdrawal` for rejected, `settle-accepted-withdrawal` for
;; accepted). This is staker-owed sBTC that has either left the contract balance
;; into the sBTC withdrawal system (pending) or been returned to the balance but
;; not yet paid out (rejected). `sweep-fee-refunds` subtracts it so an admin can
;; never sweep funds owed to a staker.
(define-data-var withdrawal-liability uint u0)

;; sBTC pulled into this contract by `claim-rewards` that has not yet been paid
;; out, split per `(reward-cycle, bond-index)`. `claim-rewards` credits each
;; bucket with the gross it received for that cycle/bond; each
;; `claim-staker-rewards` debits that staker's `gross` from the matching bucket.
;;
;; Per-bucket (rather than one global counter) so a claim against cycle A can
;; never be paid out of the reserve credited for cycle B.
;;
;; A bucket never quite reaches zero: pox-5 computes each staker's share with
;; integer division, so the sum of all per-staker `gross` is a few sats short
;; of the pot `claim-rewards` pulled in. That remainder is deliberately left
;; reserved forever rather than being released to anyone. It is staker money
;; that simply cannot be attributed to a staker, so it stays in the contract;
;; there is no path by which an admin can reach it.
;;
;; The cost of that choice: because the residue is permanently reserved, it
;; permanently reduces what `sweep-fee-refunds` can take. Since fee dust now
;; goes back to stakers via `settle-accepted-withdrawal`, the only thing that
;; sweep is still for is sBTC sent here by mistake -- and such a donation is
;; only recoverable to the extent it exceeds the accumulated residue.
(define-map unclaimed-rewards-for-cycle
    {
        reward-cycle: uint,
        bond-index: (optional uint),
    }
    uint
)

;; Sum over every bucket in `unclaimed-rewards-for-cycle`. Maintained
;; alongside the map because `sweep-fee-refunds` needs the total in one read
;; and Clarity cannot iterate a map.
(define-data-var total-unclaimed-rewards uint u0)

;; Per-staker sBTC withdrawal fee refunds, credited by
;; `settle-accepted-withdrawal` and paid out by `claim-refund`.
(define-map staker-refunds
    principal
    uint
)

;; Sum over `staker-refunds`. Reserved from `sweep-fee-refunds` so an admin
;; can never sweep a refund already credited to a staker.
(define-data-var credited-refunds uint u0)

;;; pox-5 callbacks

;; Callback function from a `stake` transaction.
;;
;; If `signer-calldata` is provided, then it must be the consensus
;; serialization of `{ pox-addr: { version, hashbytes }, max-fee, min-claim }`.
;; If provided, the payout config is saved for the user, and they'll receive
;; rewards through sBTC withdrawals.
;;
;; NOTE: the calldata tuple gained a `min-claim` field relative to v1; v1
;; calldata will not deserialize here.
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
        (ok (match signer-calldata
            calldata (begin
                (try! (store-payout-config staker calldata))
                true
            )
            ;; If `signer-calldata` is not provided, delete (if present)
            ;; their entry from `payout-configs`.
            (map-delete payout-configs staker)
        ))
    )
)

;;; Staker payout configuration

;; Set (or replace) the caller's own L1 payout config, without having to
;; re-drive `stake` / `stake-update` on pox-5. This is the escape hatch for a
;; staker whose `max-fee` / `min-claim` no longer suit current BTC fee levels.
;;
;; `contract-caller` must equal `tx-sender`: this sets where the caller's
;; rewards are sent, so an intermediary contract must not be able to set it on
;; a user's behalf mid-call.
(define-public (set-payout-config
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (max-fee uint)
        (min-claim uint)
    )
    (let ((config {
            pox-addr: pox-addr,
            max-fee: max-fee,
            min-claim: min-claim,
        }))
        (asserts! (is-eq contract-caller tx-sender) ERR_UNAUTHORIZED_CALLER)
        (try! (check-payout-config config))
        (map-set payout-configs tx-sender config)
        (print {
            topic: "set-payout-config",
            staker: tx-sender,
            config: config,
        })
        (ok true)
    )
)

;; Clear the caller's L1 payout config, reverting them to direct sBTC payouts.
(define-public (clear-payout-config)
    (begin
        (asserts! (is-eq contract-caller tx-sender) ERR_UNAUTHORIZED_CALLER)
        (print {
            topic: "clear-payout-config",
            staker: tx-sender,
        })
        (ok (map-delete payout-configs tx-sender))
    )
)

;;; Signer rewards

;; Claim rewards _as the signer manager_ contract. When new rewards are available
;; from pox-5, this function must be called before rewards will be seen as available
;; to stakers of this signer.
;;
;; This function is callable by anyone. Once called, this contract will receive sBTC,
;; and rewards information will be crystallized -- including the fee rate, which is
;; snapshotted per `(reward-cycle, bond-index)` on first crystallization and never
;; revised.
(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (let (
            (active-bips (get-active-fee-bips))
            (result (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 claim-rewards
                bond-periods reward-cycle
            )))
            (stx-key {
                reward-cycle: reward-cycle,
                bond-index: none,
            })
        )
        ;; The sBTC just pulled in is owed to this signer's stakers until each
        ;; claims via `claim-staker-rewards`; reserve it so it is not sweepable.
        (var-set total-unclaimed-rewards
            (+ (var-get total-unclaimed-rewards) (get total-rewards result))
        )
        (map-insert fee-bips-for-cycle stx-key active-bips)
        (credit-cycle-bucket stx-key (get earned (get stx-rewards result)))
        (fold snapshot-bond-rewards (get bond-rewards result) {
            reward-cycle: reward-cycle,
            bips: active-bips,
        })
        (ok result)
    )
)

;; Get the total amount of rewards earned since the last
;; rewards snapshot for this staker. Returns a tuple of `{ earned, fees }`.
;; The total portion of rewards the staker has accounted for
;; is `earned + fees`.
(define-read-only (get-earned-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (earned-before-fees (contract-call? 'ST000000000000000000002AMW42H.pox-5
                get-earned-staker-rewards current-contract reward-cycle
                bond-index staker
            ))
            (fees (/
                (* earned-before-fees
                    (get-fee-bips-for-cycle reward-cycle bond-index)
                )
                BIPS_DENOMINATOR
            ))
        )
        {
            earned: (- earned-before-fees fees),
            fees: fees,
        }
    )
)

;; Trigger a claim of rewards for a given staker.
;; Anyone can call this function, and it will transfer rewards to the
;; staker.
;;
;; If the staker has an L1 payout config, then rewards are withdrawn through
;; sBTC to their Bitcoin address. Otherwise, the staker receives sBTC.
;;
;; A third-party caller may only trigger an L1 payout once the staker's net
;; reward reaches their `min-claim`; the staker themselves may claim any
;; non-dust amount.
;;
;; Returns `{ earned, withdrawal-request }` where `earned` is the net
;; amount claimed for the staker after signer-manager fees and
;; `withdrawal-request` is `(some id)` when an L1 sBTC withdrawal was
;; initiated, or `none` for a direct sBTC payout.
(define-public (claim-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (rewards-info (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5
                claim-staker-rewards-for-signer staker reward-cycle
                bond-index
            )))
            (gross (get earned rewards-info))
            (fees (/ (* gross (get-fee-bips-for-cycle reward-cycle bond-index))
                BIPS_DENOMINATOR
            ))
            (earned (- gross fees))
            (bucket-key {
                reward-cycle: reward-cycle,
                bond-index: bond-index,
            })
            (bucket (default-to u0 (map-get? unclaimed-rewards-for-cycle bucket-key)))
            (config (get-payout-config staker))
        )
        (asserts! (> earned u0) ERR_NO_CLAIMABLE_REWARDS)
        ;; This cycle's reserve must actually cover the payout: a claim against
        ;; one cycle can never be funded out of another cycle's reserve.
        (asserts! (>= bucket gross) ERR_NO_CLAIMABLE_REWARDS)
        ;; Anyone may trigger a claim, but forcing a *Bitcoin* payout costs the
        ;; staker up to `max-fee` in miner fees. Only the staker may do that
        ;; below the floor they set.
        (asserts!
            (or (is-eq tx-sender staker)
                (match config
                    l1-info (>= earned (get min-claim l1-info))
                    true
                ))
            ERR_BELOW_MIN_CLAIM
        )
        (var-set earned-fees (+ (var-get earned-fees) fees))
        ;; This staker's share is being distributed now so release it from
        ;; the unclaimed counts recorded when `claim-rewards` pulled it in.
        (map-set unclaimed-rewards-for-cycle bucket-key (- bucket gross))
        (var-set total-unclaimed-rewards
            (- (var-get total-unclaimed-rewards) gross)
        )
        ;; Bind the request-id surfaced when the payout was routed to L1 via
        ;; `initiate-withdrawal-request`, `none` when the staker was paid
        ;; directly in sBTC.
        (let ((withdrawal-request (try! (as-contract?
                ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                    "sbtc-token" earned
                ))
                (match config
                    l1-info (let ((max-fee (get max-fee l1-info)))
                        ;; `initiate-withdrawal-request` asserts
                        ;; `(> amount DUST_LIMIT)` on `earned - max-fee`.
                        ;; Check it here so an unpayable claim fails with our
                        ;; error rather than an opaque sBTC one -- and so the
                        ;; subtraction below cannot underflow.
                        (asserts! (> earned (+ max-fee DUST_LIMIT))
                            ERR_BELOW_DUST_LIMIT
                        )
                        (let (
                                (amount (- earned max-fee))
                                (withdrawal-request (try! (contract-call?
                                    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal
                                    initiate-withdrawal-request amount
                                    (get pox-addr l1-info) max-fee
                                )))
                            )
                            (print {
                                topic: "claim-staker-rewards",
                                amount-sats: earned,
                                l1-withdrawal: (some (merge l1-info {
                                    withdrawal-request: withdrawal-request,
                                    amount: amount,
                                })),
                                staker: staker,
                                reward-cycle: reward-cycle,
                                bond-index: bond-index,
                            })
                            (map-set withdrawal-requests withdrawal-request staker)
                            ;; `amount + max-fee` == `earned` left the balance
                            ;; into the sBTC withdrawal system; record it as
                            ;; staker liability.
                            (var-set withdrawal-liability
                                (+ (var-get withdrawal-liability) earned)
                            )
                            (some withdrawal-request)
                        )
                    )
                    (begin
                        (print {
                            topic: "claim-staker-rewards",
                            amount-sats: earned,
                            l1-withdrawal: none,
                            staker: staker,
                            reward-cycle: reward-cycle,
                            bond-index: bond-index,
                        })
                        (try! (contract-call?
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            transfer earned tx-sender staker none
                        ))
                        ;; Direct sBTC payout: there is no L1 withdrawal to track.
                        none
                    )
                )))))
            (ok {
                earned: earned,
                withdrawal-request: withdrawal-request,
            })
        )
    )
)

;;; Withdrawal settlement

;; Reclaim a REJECTED L1 withdrawal back to the staker who earned it.
;;
;; `claim-staker-rewards` initiates the sBTC withdrawal inside `as-contract?`,
;; meaning this contract is the withdrawal's requester. Any sBTC the sBTC
;; protocol returns for that request therefore goes to this contract, not the
;; staker whose pox-5 balance was already zeroed. Two cases:
;;   * REJECTED  -> the full `amount + max-fee` is unlocked back to the
;;                  requester, and paid out here.
;;   * ACCEPTED  -> only the unused fee budget (`max-fee - actual-fee`) is
;;                  minted back; `settle-accepted-withdrawal` credits it to the
;;                  staker.
;;
;; Permissionless, mirroring `claim-staker-rewards`: anyone may trigger it on a
;; staker's behalf. The `withdrawal-requests` entry is deleted so the reclaim
;; cannot be replayed.
(define-public (reclaim-failed-withdrawal (request-id uint))
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
        ;; Request is settled: drop it from the outstanding staker liability.
        (var-set withdrawal-liability (- (var-get withdrawal-liability) refund))
        (print {
            topic: "reclaim-failed-withdrawal",
            request-id: request-id,
            staker: staker,
            amount-sats: refund,
        })
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" refund
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer refund tx-sender staker none
            ))
        ))
        (ok refund)
    )
)

;; Settle an ACCEPTED L1 withdrawal and credit its unused fee budget back to
;; the staker.
;;
;; On acceptance the sBTC protocol pays the staker on L1 and mints only the
;; unused fee budget (`max-fee - actual-fee`) back to this contract. That
;; budget came out of the staker's own rewards, so it is theirs. The sBTC
;; registry does not store the actual fee paid (it appears only in an event),
;; so the amount is recovered from the balance instead: once this request's
;; liability is released, the unreserved balance is exactly what came back for
;; it, capped at `max-fee` as a safety bound.
;;
;; CAVEAT: that inference is exact when withdrawals are settled one at a time,
;; which is the normal case since this call is permissionless and the staker is
;; the one paid. With several accepted-but-unsettled requests outstanding, the
;; still-reserved liability of the others suppresses the reading, so an early
;; settler may be credited less than their true refund and a later one more.
;; The total is conserved and never reaches an admin -- `credited-refunds` is
;; reserved from `sweep-fee-refunds` -- but stakers should settle promptly.
;;
;; Mirrors `reclaim-failed-withdrawal` (permissionless, deletes the entry to
;; prevent replay) but for the accept case.
(define-public (settle-accepted-withdrawal (request-id uint))
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
            (max-fee (get max-fee request))
            (liability (+ (get amount request) max-fee))
        )
        ;; `status` is `none` while pending and `(some false)` if rejected;
        ;; only `(some true)` (accepted) is settleable here. Rejected requests
        ;; must go through `reclaim-failed-withdrawal` so the staker is paid.
        (asserts! (is-eq (get status request) (some true))
            ERR_WITHDRAWAL_NOT_ACCEPTED
        )
        (map-delete withdrawal-requests request-id)
        ;; Request is settled: drop it from the outstanding staker liability.
        (var-set withdrawal-liability
            (- (var-get withdrawal-liability) liability)
        )
        (let ((refund (min-uint max-fee (unattributed-balance))))
            (if (> refund u0)
                (begin
                    (map-set staker-refunds staker
                        (+ (get-staker-refund staker) refund)
                    )
                    (var-set credited-refunds
                        (+ (var-get credited-refunds) refund)
                    )
                )
                true
            )
            (print {
                topic: "settle-accepted-withdrawal",
                request-id: request-id,
                staker: staker,
                liability-released: liability,
                fee-refund: refund,
            })
            (ok refund)
        )
    )
)

;; Pay out a staker's credited sBTC withdrawal fee refunds.
;; Permissionless: anyone may trigger it, the funds always go to `staker`.
(define-public (claim-refund (staker principal))
    (let ((refund (get-staker-refund staker)))
        (asserts! (> refund u0) ERR_NO_REFUND_CREDIT)
        (map-delete staker-refunds staker)
        (var-set credited-refunds (- (var-get credited-refunds) refund))
        (print {
            topic: "claim-refund",
            staker: staker,
            amount-sats: refund,
        })
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" refund
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer refund tx-sender staker none
            ))
        ))
        (ok refund)
    )
)

;;; Admin functions

;; Update the allowed admin principals. The last remaining admin cannot be
;; removed -- doing so would permanently disable `update-fees`,
;; `withdraw-fees`, `sweep-fee-refunds` and `register-self`, stranding any
;; accrued fees.
(define-public (update-admin
        (admin principal)
        (enabled bool)
    )
    (let ((was-admin (is-admin admin)))
        (try! (authorize-admin))
        (asserts! (or enabled (not was-admin) (> (var-get admin-count) u1))
            ERR_LAST_ADMIN
        )
        (if (is-eq was-admin enabled)
            true
            (begin
                (var-set admin-count (if enabled
                    (+ (var-get admin-count) u1)
                    (- (var-get admin-count) u1)
                ))
                (map-set admins admin enabled)
            )
        )
        (print {
            topic: "update-admin",
            admin: admin,
            enabled: enabled,
            admin-count: (var-get admin-count),
        })
        (ok admin)
    )
)

;; Update the fees taken from rewards.
;;
;; A *decrease* applies immediately -- it can only benefit stakers. An
;; *increase* is queued and does not become snapshottable until
;; `FEE_ACTIVATION_DELAY_CYCLES` cycles from now, so a staker who dislikes the
;; new rate has time to unstake before any of their rewards are crystallized
;; at it. Because `claim-rewards` snapshots the rate per cycle, a queued
;; increase also cannot reach back into a cycle that has already been pulled.
(define-public (update-fees (new-fees uint))
    (let (
            (active (get-active-fee-bips))
            (cycle (current-cycle))
        )
        (try! (authorize-admin))
        (asserts! (<= new-fees MAX_FEE_BIPS) ERR_INVALID_FEES_BIPS)
        ;; Collapse any already-matured pending rate into the active slot, so
        ;; that queueing a new change never resurrects the pre-pending rate.
        (var-set fees-bips active)
        (if (<= new-fees active)
            (begin
                (var-set fees-bips new-fees)
                (var-set pending-fees-bips new-fees)
                (var-set pending-fees-cycle cycle)
            )
            (begin
                (var-set pending-fees-bips new-fees)
                (var-set pending-fees-cycle
                    (+ cycle FEE_ACTIVATION_DELAY_CYCLES)
                )
            )
        )
        (print {
            topic: "update-fees",
            old-fees: active,
            new-fees: new-fees,
            activation-cycle: (var-get pending-fees-cycle),
        })
        (ok true)
    )
)

;; Withdraw accrued admin fees from staker rewards.
(define-public (withdraw-fees
        (amount uint)
        (recipient principal)
    )
    (let ((fees (var-get earned-fees)))
        (try! (authorize-admin))
        (asserts! (<= amount fees) ERR_INSUFFICIENT_FEES)
        (var-set earned-fees (- fees amount))
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" amount
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer amount tx-sender recipient none
            ))
        ))
        (ok amount)
    )
)

;; Sweep sBTC that belongs to nobody to a recipient.
;;
;; In v1 this was how accepted-withdrawal fee dust was recovered. That dust now
;; goes back to the staker who earned it via `settle-accepted-withdrawal`, so
;; the only thing left for this to sweep is sBTC sent here by mistake -- and
;; only the part of it that exceeds the permanently-reserved rounding residue
;; described on `unclaimed-rewards-for-cycle`.
;;
;; The full unreserved amount is taken: the sBTC balance minus the fee
;; accumulator (`earned-fees`), the outstanding `withdrawal-liability`, the
;; pooled `unclaimed-rewards-for-cycle` totals, and `credited-refunds`, so it
;; can NEVER sweep funds owed to a staker. A rejected-but-unreclaimed
;; withdrawal's `amount + max-fee` is present in BOTH the sBTC balance (the
;; protocol returned it here) and in `withdrawal-liability` (the entry is still
;; live), so the two cancel and the refund stays untouchable, whether or not
;; anyone has called `reclaim-failed-withdrawal` yet.
(define-public (sweep-fee-refunds (recipient principal))
    (let ((sweepable (unattributed-balance)))
        (try! (authorize-admin))
        (asserts! (> sweepable u0) ERR_NO_REFUNDS)
        (print {
            topic: "sweep-fee-refunds",
            amount-sats: sweepable,
            recipient: recipient,
        })
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" sweepable
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer sweepable tx-sender recipient none
            ))
        ))
        (ok sweepable)
    )
)

;; As an admin, register this contract with a specific signer key. The signer key grant
;; must not have been used yet.
(define-public (register-self
        (signer-manager <signer-manager-trait>)
        (signer-key (buff 33))
        (auth-id uint)
        (signer-sig (buff 65))
    )
    (begin
        (try! (authorize-admin))
        ;; pox-5's `register-signer` also enforces this (it asserts
        ;; `contract-caller` is the trait principal), but assert it here so the
        ;; failure names this contract instead of surfacing a pox-5 error. The
        ;; parameter cannot be dropped: `register-signer` takes a trait
        ;; reference, which Clarity cannot synthesize from `current-contract`.
        (asserts! (is-eq (contract-of signer-manager) current-contract)
            ERR_NOT_SELF
        )
        (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 grant-signer-key
            signer-key current-contract auth-id signer-sig
        ))
        (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-signer
            signer-manager signer-key
        )
    )
)

;;; Private helpers

(define-private (authorize-admin)
    (ok (asserts! (and (is-eq contract-caller tx-sender) (is-admin tx-sender))
        ERR_UNAUTHORIZED_ADMIN
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

;; Deserialize and store an L1 payout config supplied as pox-5 calldata.
(define-private (store-payout-config
        (staker principal)
        (calldata (buff 500))
    )
    (let ((config (unwrap!
            (from-consensus-buff? {
                pox-addr: {
                    version: (buff 1),
                    hashbytes: (buff 32),
                },
                max-fee: uint,
                min-claim: uint,
            }
                calldata
            )
            ERR_INVALID_CALLDATA
        )))
        (try! (check-payout-config config))
        (map-set payout-configs staker config)
        (ok true)
    )
)

(define-private (credit-cycle-bucket
        (key {
            reward-cycle: uint,
            bond-index: (optional uint),
        })
        (amount uint)
    )
    (map-set unclaimed-rewards-for-cycle key
        (+ (default-to u0 (map-get? unclaimed-rewards-for-cycle key)) amount)
    )
)

(define-private (snapshot-bond-rewards
        (bond-info {
            bond-index: uint,
            earned: uint,
            rewards-per-token: uint,
        })
        (acc {
            reward-cycle: uint,
            bips: uint,
        })
    )
    (let ((key {
            reward-cycle: (get reward-cycle acc),
            bond-index: (some (get bond-index bond-info)),
        }))
        (map-insert fee-bips-for-cycle key (get bips acc))
        (credit-cycle-bucket key (get earned bond-info))
        acc
    )
)

;;; Read-only views

(define-read-only (is-admin (caller principal))
    (default-to false (map-get? admins caller))
)

(define-read-only (get-admin-count)
    (var-get admin-count)
)

(define-read-only (current-cycle)
    (contract-call? 'ST000000000000000000002AMW42H.pox-5 current-pox-reward-cycle)
)

;; The fee rate a `claim-rewards` call would snapshot right now: the pending
;; rate once its activation cycle is reached, otherwise the previous one.
(define-read-only (get-active-fee-bips)
    (if (>= (current-cycle) (var-get pending-fees-cycle))
        (var-get pending-fees-bips)
        (var-get fees-bips)
    )
)

;; The queued rate change, for stakers deciding whether to unstake.
(define-read-only (get-pending-fees)
    {
        pending-bips: (var-get pending-fees-bips),
        activation-cycle: (var-get pending-fees-cycle),
        active-bips: (get-active-fee-bips),
    }
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

(define-read-only (get-earned-fees)
    (var-get earned-fees)
)

(define-read-only (get-withdrawal-liability)
    (var-get withdrawal-liability)
)

(define-read-only (get-unclaimed-staker-rewards)
    (var-get total-unclaimed-rewards)
)

(define-read-only (get-unclaimed-rewards-for-cycle
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (default-to u0
        (map-get? unclaimed-rewards-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
        })
    )
)

(define-read-only (get-payout-config (staker principal))
    (map-get? payout-configs staker)
)

(define-read-only (get-staker-refund (staker principal))
    (default-to u0 (map-get? staker-refunds staker))
)

(define-read-only (get-credited-refunds)
    (var-get credited-refunds)
)

(define-read-only (get-withdrawal-request-staker (withdrawal-request uint))
    (map-get? withdrawal-requests withdrawal-request)
)

;; sBTC held by this contract that is not spoken for by fees, live
;; withdrawals, unclaimed staker rewards, or credited refunds.
(define-read-only (unattributed-balance)
    (let (
            (balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
            (reserved (+ (var-get earned-fees) (var-get withdrawal-liability)
                (var-get total-unclaimed-rewards) (var-get credited-refunds)
            ))
        )
        (if (>= balance reserved)
            (- balance reserved)
            u0
        )
    )
)

;; Validate an L1 payout config.
;;
;; The pox-addr rules are sBTC's, not ours: delegate to
;; `.sbtc-withdrawal validate-recipient` rather than reimplementing them, so
;; the two can never drift and leave a staker with an address this contract
;; accepts but the withdrawal path rejects.
;;
;; `min-claim` must exceed `max-fee + DUST_LIMIT` so that any claim which
;; clears the floor also clears the sBTC dust limit.
(define-read-only (check-payout-config (config {
    pox-addr: {
        version: (buff 1),
        hashbytes: (buff 32),
    },
    max-fee: uint,
    min-claim: uint,
}))
    (begin
        (asserts!
            (is-ok (contract-call?
                'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal
                validate-recipient (get pox-addr config)
            ))
            ERR_INVALID_POX_ADDR
        )
        (asserts!
            (> (get min-claim config) (+ (get max-fee config) DUST_LIMIT))
            ERR_INVALID_MIN_CLAIM
        )
        (ok true)
    )
)

(define-read-only (min-uint
        (a uint)
        (b uint)
    )
    (if (< a b)
        a
        b
    )
)
