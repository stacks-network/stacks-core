;; Reference implementation for the signer manager trait, to be used with pox-5.
;;
;; This contract allows stakers to set a `pox-addr` that, when present, allows
;; rewards to be automatically withdrawn to BTC via an sBTC withdrawal. Anyone
;; can trigger this withdrawal, which allows for passively receiving L1 rewards.
;;
;; Admins of this contract can set fees. When fees are set, they are automatically
;; deducted from any stakers _newly calculated_ rewards. That means that if a staker
;; has not had their rewards crystallized in some amount of time, then a new fee
;; rate is set, the next time `claim-rewards` is called will have fees taken
;; from rewards _even before_ the fee was set. The rate is then fixed for that cycle.

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
;; A staker-only function called through another contract also uses this error.
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

;; The payout amount is zero or exceeds the pending balance.
(define-constant ERR_INSUFFICIENT_PENDING (err u1012))
;; A third party tried an L1 payout below the staker minimum.
(define-constant ERR_BELOW_MIN_CLAIM (err u1013))
;; The L1 withdrawal amount does not clear the sBTC dust limit.
(define-constant ERR_BELOW_DUST_LIMIT (err u1014))
;; The allowlist is enabled and the staker is not listed.
(define-constant ERR_NOT_ALLOWLISTED (err u1015))

(define-constant DUST_LIMIT u546)

(define-constant MAX_BIPS u10000)

;; default to allowing deployer to register as a pool
(define-map admins
    principal
    bool
)
(map-set admins tx-sender true)

;; Fees taken, in basis points, from rewards
(define-data-var fees-bips uint u0)

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
;; A staker's payout destination, including the floor for third-party L1 claims.
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

;; Mapping of a given withdrawal request ID to the staker
;; whose rewards created that withdrawal.
(define-map withdrawal-requests
    uint
    principal
)

;; Sum of `amount + max-fee` over every live (un-settled) entry in
;; `withdrawal-requests`. Incremented when a withdrawal is initiated in
;; `payout` and decremented when the request is settled
;; (`reclaim-failed-withdrawal` for rejected, `settle-accepted-withdrawal` for
;; accepted). This is staker-owed sBTC that has either left the contract balance
;; into the sBTC withdrawal system (pending) or been returned to the balance but
;; not yet paid out (rejected). `sweep-fee-refunds` subtracts it so an admin can
;; never sweep funds owed to a staker -- see the note on that function.
(define-data-var withdrawal-liability uint u0)

;; sBTC pulled into this contract by `claim-rewards` that has not yet been
;; allocated to a staker via `settle-staker-rewards`. `claim-rewards` adds
;; the gross `total-rewards` it received; each `settle-staker-rewards` subtracts
;; that staker's `gross` as it moves into pending payout and earned fees. Like
;; `withdrawal-liability`, this is subtracted in `sweep-fee-refunds` so an
;; admin can never sweep staker rewards.
(define-data-var unclaimed-staker-rewards uint u0)

(define-map pending-payouts principal uint)
(define-data-var total-pending uint u0)

;; Rewards are reserved per cycle and bond index until stakers settle them.
(define-map unclaimed-staker-rewards-for-cycle
    { reward-cycle: uint, bond-index: (optional uint) }
    uint
)

(define-data-var use-allowlist bool false)
(define-map allowlist principal bool)
(define-data-var token-uri (optional (string-utf8 256)) none)

;; Callback function from a `stake` transaction.
;;
;; If `signer-calldata` is provided, then it must be a payout config. If provided,
;; the config is saved for the user. Without calldata, the stored config is deleted.
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
        (asserts! (or (not (var-get use-allowlist)) (is-allowlisted staker))
            ERR_NOT_ALLOWLISTED
        )
        (match signer-calldata
            calldata (let ((config (try! (parse-payout-config calldata))))
                (try! (check-payout-config config))
                (ok (map-set payout-configs staker config))
            )
            (ok (map-delete payout-configs staker))
        )
    )
)

;; Claim rewards _as the signer manager_ contract. When new rewards are available
;; from pox-5, this function must be called before rewards will be seen as available
;; to stakers of this signer.
;;
;; This function is callable by anyone. Once called, this contract will receive sBTC,
;; and rewards information will be crystallized.
(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (let ((result (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 claim-rewards
            bond-periods reward-cycle
        ))))
        ;; The sBTC just pulled in is owed to this signer's stakers until each
        ;; settles via `settle-staker-rewards`; reserve it so it is not sweepable.
        (reserve-rewards reward-cycle none (get earned (get stx-rewards result)))
        (fold reserve-bond-rewards (get bond-rewards result) reward-cycle)
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

;;; Staker rewards

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
                MAX_BIPS
            ))
        )
        {
            earned: (- earned-before-fees fees),
            fees: fees,
        }
    )
)

;; Move one staker's reward from its cycle reserve into their pending balance.
(define-public (settle-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (key { reward-cycle: reward-cycle, bond-index: bond-index })
            (gross (get earned
                (unwrap-panic (contract-call? 'ST000000000000000000002AMW42H.pox-5
                    claim-staker-rewards-for-signer staker reward-cycle bond-index
                ))
            ))
            (reserve (get-unclaimed-staker-rewards-for-cycle reward-cycle bond-index))
            (fee (/ (* gross (get-fee-bips-for-cycle reward-cycle bond-index)) MAX_BIPS))
        )
        (asserts! (> gross u0) ERR_NO_CLAIMABLE_REWARDS)
        (asserts! (>= reserve gross) ERR_NO_CLAIMABLE_REWARDS)
        (map-set unclaimed-staker-rewards-for-cycle key (- reserve gross))
        (var-set unclaimed-staker-rewards (- (var-get unclaimed-staker-rewards) gross))
        (var-set earned-fees (+ (var-get earned-fees) fee))
        (credit-pending staker (- gross fee))
        (print {
            topic: "settle-staker-rewards",
            staker: staker,
            reward-cycle: reward-cycle,
            bond-index: bond-index,
            amount-sats: gross,
        })
        (ok { gross: gross, fee: fee })
    )
)

;; Pay the full pending balance to the staker's configured destination.
(define-public (payout (staker principal))
    (let (
            (amount (get-pending-payout staker))
            (config (default-to { l1-withdrawal: none, sbtc-recipient: none }
                (map-get? payout-configs staker)
            ))
        )
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
            (ok { amount: amount, withdrawal-request: withdrawal-request })
        )
    )
)

;; Trigger a claim of rewards for a given staker.
;; Anyone can call this function, and it will pay rewards using the
;; staker's payout config.
;;
;; If the staker has an L1 payout config, then rewards are withdrawn through
;; sBTC to their Bitcoin address. Otherwise, the staker receives sBTC.
;;
;; Returns `{ earned, withdrawal-request }` where `earned` is the net
;; amount paid from the staker's accumulated pending balance after
;; signer-manager fees and `withdrawal-request` is `(some id)` when an L1 sBTC
;; withdrawal was initiated, or `none` for a direct sBTC payout.
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

;; Only the staker may choose their payout destination.
(define-public (set-payout-config
        (l1-withdrawal (optional {
            pox-addr: { version: (buff 1), hashbytes: (buff 32) },
            max-fee: uint,
            min-claim: uint,
        }))
        (sbtc-recipient (optional principal))
    )
    (begin
        (try! (authorize-staker))
        (let ((config {
                l1-withdrawal: l1-withdrawal,
                sbtc-recipient: sbtc-recipient,
            }))
            (try! (check-payout-config config))
            (print { topic: "set-payout-config", staker: tx-sender, config: config })
            (ok (map-set payout-configs tx-sender config))
        )
    )
)

(define-public (clear-payout-config)
    (begin
        (try! (authorize-staker))
        (print { topic: "clear-payout-config", staker: tx-sender })
        (ok (map-delete payout-configs tx-sender))
    )
)

;; Reclaim a REJECTED L1 withdrawal for the staker who earned it.
;;
;; `payout` initiates the sBTC withdrawal inside `as-contract?`,
;; meaning this contract is the withdrawal's requester. Any sBTC the sBTC
;; protocol returns for that request therefore goes to this contract, not the
;; staker whose pox-5 balance was already zeroed. Two cases:
;;   * REJECTED  -> the full `amount + max-fee` is unlocked back to the
;;                  requester. Credited to the staker's pending payout.
;;   * ACCEPTED  -> only the unused fee budget (`max-fee - actual-fee`) is
;;                  minted back. The actual fee is not exposed by the sBTC
;;                  registry, so this dust cannot be attributed to a single
;;                  staker; it is recovered via `sweep-fee-refunds`.
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
        (credit-pending staker refund)
        (ok refund)
    )
)

;; Reclaim a rejected L1 withdrawal and pay using the current configuration.
(define-public (retry-failed-withdrawal (request-id uint))
    (let ((staker (unwrap! (map-get? withdrawal-requests request-id)
            ERR_UNKNOWN_WITHDRAWAL_REQUEST
        )))
        (try! (reclaim-failed-withdrawal request-id))
        (payout staker)
    )
)

;; Settle an ACCEPTED L1 withdrawal.
;;
;; On acceptance the sBTC protocol pays the staker on L1 and mints only the
;; unused fee budget (`max-fee - actual-fee`) back to this contract as dust. No
;; staker payout is owed here, but the request is still counted in
;; `withdrawal-liability` (at its full `amount + max-fee`), which suppresses the
;; sweepable balance. This permissionless call retires the entry so that:
;;   * its liability is released, and
;;   * the accept-case dust it left behind becomes sweepable via
;;     `sweep-fee-refunds`.
;;
;; Mirrors `reclaim-failed-withdrawal` (permissionless, deletes the entry to
;; prevent replay) but for the accept case, where there is nothing to pay out.
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
            (liability (+ (get amount request) (get max-fee request)))
        )
        ;; `status` is `none` while pending and `(some false)` if rejected;
        ;; only `(some true)` (accepted) is settleable here. Rejected requests
        ;; must go through `reclaim-failed-withdrawal` so the staker is credited.
        (asserts! (is-eq (get status request) (some true))
            ERR_WITHDRAWAL_NOT_ACCEPTED
        )
        (map-delete withdrawal-requests request-id)
        ;; Request is settled: drop it from the outstanding staker liability.
        ;; The dust already minted to this contract stays in the balance and is
        ;; now sweepable.
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

(define-public (set-use-allowlist (enabled bool))
    (begin
        (try! (authorize-admin))
        (print { topic: "set-use-allowlist", enabled: enabled })
        (ok (var-set use-allowlist enabled))
    )
)

(define-public (set-allowlisted (staker principal) (allowed bool))
    (begin
        (try! (authorize-admin))
        (print { topic: "set-allowlisted", staker: staker, allowed: allowed })
        (ok (map-set allowlist staker allowed))
    )
)

(define-public (set-token-uri (uri (optional (string-utf8 256))))
    (begin
        (try! (authorize-admin))
        (print { topic: "set-token-uri", uri: uri })
        (ok (var-set token-uri uri))
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

;; Sweep orphaned sBTC fee-refund dust to a recipient.
;;
;; On an ACCEPTED withdrawal the sBTC protocol mints the unused fee budget
;; (`max-fee - actual-fee`) back to this contract. That dust cannot be
;; attributed to a specific staker on-chain (the sBTC registry does not expose
;; the actual fee paid), so it pools here; this admin-gated function sweeps it.
;;
;; The full sweepable amount is taken: the sBTC balance minus the fee
;; accumulator (`earned-fees`), the outstanding `withdrawal-liability`, the
;; pooled `unclaimed-staker-rewards` that `claim-rewards` pulled in but no staker
;; has settled yet, and `total-pending`, so it can NEVER sweep funds owed to a staker. A
;; rejected-but-unreclaimed withdrawal's `amount + max-fee` is present in BOTH
;; the sBTC balance (the protocol returned it here) and in
;; `withdrawal-liability` (the entry is still live), so the two cancel and the
;; refund stays untouchable, whether or not anyone has called
;; `reclaim-failed-withdrawal` yet.
;;
;; The flip side: while a withdrawal is pending, or accepted but not yet retired
;; via `settle-accepted-withdrawal`, its full `amount + max-fee` suppresses the
;; sweepable amount. To recover the accept-case fee dust an admin must first
;; `settle-accepted-withdrawal` the accepted requests (and wait for any pending
;; ones to finalize).
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
        (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 grant-signer-key
            signer-key current-contract auth-id signer-sig
        ))
        (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-signer
            signer-manager signer-key
        )
    )
)

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

(define-read-only (is-admin (caller principal))
    (default-to false (map-get? admins caller))
)

(define-private (snapshot-bond-fee
        (bond-info {
            bond-index: uint,
            earned: uint,
            rewards-per-token: uint,
        })
        ;; #[allow(unused_binding)]
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

(define-private (authorize-staker)
    (ok (asserts! (is-eq contract-caller tx-sender) ERR_UNAUTHORIZED_CALLER))
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
        (map-set unclaimed-staker-rewards-for-cycle key
            (+ (default-to u0 (map-get? unclaimed-staker-rewards-for-cycle key)) amount)
        )
        (var-set unclaimed-staker-rewards (+ (var-get unclaimed-staker-rewards) amount))
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

;; Request an L1 withdrawal of `amount - max-fee` to the staker's address.
;; Record the request under this contract so it can settle the result.
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
    (var-get unclaimed-staker-rewards)
)

(define-read-only (get-withdrawal-request-staker (withdrawal-request uint))
    (map-get? withdrawal-requests withdrawal-request)
)

;; Decode a payout config from staking calldata.
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

;; Use the sBTC withdrawal contract to validate an L1 recipient. It applies
;; the same rules as `initiate-withdrawal-request`.
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
        l1 (check-pox-addr (get pox-addr l1))
        (ok true)
    )
)

(define-read-only (get-payout-config (staker principal))
    (map-get? payout-configs staker)
)

(define-read-only (get-use-allowlist)
    (var-get use-allowlist)
)

(define-read-only (is-allowlisted (staker principal))
    (default-to false (map-get? allowlist staker))
)

(define-read-only (get-token-uri)
    (ok (var-get token-uri))
)

(define-read-only (get-pending-payout (staker principal))
    (default-to u0 (map-get? pending-payouts staker))
)

(define-read-only (get-unclaimed-staker-rewards-for-cycle
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (default-to u0
        (map-get? unclaimed-staker-rewards-for-cycle {
            reward-cycle: reward-cycle,
            bond-index: bond-index,
        })
    )
)

(define-read-only (get-reserved-balance)
    (+ (var-get earned-fees) (var-get unclaimed-staker-rewards) (var-get total-pending)
        (var-get withdrawal-liability)
    )
)


(define-read-only (check-pox-addr (pox-addr {
    version: (buff 1),
    hashbytes: (buff 32),
}))
    (ok (asserts!
        (is-ok (contract-call?
            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal
            validate-recipient pox-addr
        ))
        ERR_INVALID_POX_ADDR
    ))
)
