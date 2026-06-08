;; Reference implementation for the signer manager trait, to be used with pox-5.
;;
;; This contract allows stakers to set a `pox-addr` that, when present, allows
;; rewards to be automatically withdrawn to BTC via an sBTC withdrawal. Anyone
;; can trigger this withdrawal, which allows for passively receiving L1 rewards.
;;
;; Admins of this contract can set fees. When fees are set, they are automatically
;; deducted from any stakers _newly calculated_ rewards. That means that if a staker
;; has not claimed or crystallized rewards in some amount of time, then a new fee
;; rate is set, the next time that staker claims rewards will have fees taken
;; from reward _even before_ the fee was set.

(impl-trait .pox-5.signer-manager-trait)
(use-trait signer-manager-trait .pox-5.signer-manager-trait)

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
;; The given withdrawal-request id is not tracked by this contract.
(define-constant ERR_UNKNOWN_WITHDRAWAL_REQUEST (err u1010))
;; The withdrawal request has not been rejected, so its full
;; `amount + max-fee` is not reclaimable for the staker.
(define-constant ERR_WITHDRAWAL_NOT_REJECTED (err u1011))
;; Tried to sweep more sBTC than is safely sweepable.
(define-constant ERR_INVALID_SWEEP_AMOUNT (err u1012))
;; The withdrawal request has not been accepted, so it cannot be
;; settled via `settle-accepted-withdrawal`.
(define-constant ERR_WITHDRAWAL_NOT_ACCEPTED (err u1013))

(define-constant MAX_BIPS u10000)

;; Maximum value of an address version as a uint
(define-constant MAX_ADDRESS_VERSION u6)
;; Maximum value of an address version that has a 20-byte hashbytes
;; (0x00, 0x01, 0x02, 0x03, and 0x04 have 20-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_20 u4)

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

;; When stakers provide L1 withdrawal info as calldata,
;; that is stored here.
(define-map pox-addrs
    principal
    {
        pox-addr: {
            version: (buff 1),
            hashbytes: (buff 32),
        },
        max-fee: uint,
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
;; never sweep funds owed to a staker -- see the note on that function.
(define-data-var withdrawal-liability uint u0)

;; sBTC pulled into this contract by `claim-rewards` that has not yet been paid
;; out to an individual staker via `claim-staker-rewards`. `claim-rewards` adds
;; the gross `total-rewards` it received; each `claim-staker-rewards` subtracts
;; that staker's `gross` as it is distributed (whether paid as sBTC, sent for
;; an L1 withdrawal, or retained as a signer-manager fee). Like
;; `withdrawal-liability`, this is subtracted in `sweep-fee-refunds` so an
;; admin can never sweep staker rewards.
(define-data-var unclaimed-staker-rewards uint u0)

;; Callback function from a `stake` transaction.
;;
;; If `signer-calldata` is provided, then it must be in the form
;; of `{ version, hashbytes }` as a pox-addr. If provided, the pox-addr
;; is saved for the user, and they'll receive rewards through sBTC withdrawals.
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
            calldata
            (let ((pox-addr (unwrap!
                    (from-consensus-buff? {
                        pox-addr: {
                            version: (buff 1),
                            hashbytes: (buff 32),
                        },
                        max-fee: uint,
                    }
                        calldata
                    )
                    ERR_INVALID_CALLDATA
                )))
                (map-set pox-addrs staker pox-addr)
                true
            )
            ;; If `signer-calldata` is not provided, delete (if present)
            ;; their entry from `pox-addrs`.
            (map-delete pox-addrs staker)
        ))
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
    (let ((result (try! (contract-call? .pox-5 claim-rewards bond-periods reward-cycle))))
        ;; The sBTC just pulled in is owed to this signer's stakers until each
        ;; claims via `claim-staker-rewards`; reserve it so it is not sweepable.
        (var-set unclaimed-staker-rewards
            (+ (var-get unclaimed-staker-rewards) (get total-rewards result))
        )
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
        (is-bond bool)
        (index uint)
    )
    (let (
            (earned-before-fees (contract-call? .pox-5 get-earned-staker-rewards current-contract
                is-bond index staker
            ))
            (fees (/ (* earned-before-fees (var-get fees-bips)) MAX_BIPS))
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
;; If the staker provided a `pox-addr` as calldata while staking, then
;; rewards are withdrawn through sBTC to their L1 Bitcoin address. Otherwise,
;; the staker receives sBTC.
(define-public (claim-staker-rewards
        (staker principal)
        (is-bond bool)
        (index uint)
    )
    (let (
            ;; `unwrap-panic` is ok here: there is no `err` type returnable
            (rewards-info (unwrap-panic (contract-call? .pox-5 claim-staker-rewards-for-signer staker is-bond
                index
            )))
            (prev-fees (var-get earned-fees))
            (gross (get earned rewards-info))
            (fees (/ (* gross (var-get fees-bips)) MAX_BIPS))
            (earned (- gross fees))
        )
        (asserts! (> earned u0) ERR_NO_CLAIMABLE_REWARDS)
        (asserts!
            (>
                (unwrap-panic (contract-call?
                    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                    get-balance current-contract
                ))
                u0
            )
            ERR_NO_CLAIMABLE_REWARDS
        )
        (var-set earned-fees (+ prev-fees fees))
        ;; This staker's share is being distributed now so release it from
        ;; the unclaimed count recorded when `claim-rewards` pulled it in.
        (var-set unclaimed-staker-rewards
            (- (var-get unclaimed-staker-rewards) gross)
        )
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" earned
            ))
            (match (get-pox-addr staker)
                l1-info (let (
                        (amount (try! (if (>= earned (get max-fee l1-info))
                            (ok (- earned (get max-fee l1-info)))
                            ERR_NO_CLAIMABLE_REWARDS
                        )))
                        (withdrawal-request (try! (contract-call?
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal
                            initiate-withdrawal-request amount
                            (get pox-addr l1-info) (get max-fee l1-info)
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
                        index: index,
                        is-bond: is-bond,
                    })
                    (map-set withdrawal-requests withdrawal-request staker)
                    ;; `amount + max-fee` == `earned` left the balance into the
                    ;; sBTC withdrawal system; record it as staker liability.
                    (var-set withdrawal-liability
                        (+ (var-get withdrawal-liability)
                            (+ amount (get max-fee l1-info))
                        ))
                    true
                )
                (begin
                    (print {
                        topic: "claim-staker-rewards",
                        amount-sats: earned,
                        l1-withdrawal: none,
                        staker: staker,
                        index: index,
                        is-bond: is-bond,
                    })
                    (try! (contract-call?
                        'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                        transfer earned tx-sender staker none
                    ))
                )
            )))

        (ok earned)
    )
)

;; Reclaim a REJECTED L1 withdrawal back to the staker who earned it.
;;
;; `claim-staker-rewards` initiates the sBTC withdrawal inside `as-contract?`,
;; meaning this contract is the withdrawal's requester. Any sBTC the sBTC
;; protocol returns for that request therefore goes to this contract, not the
;; staker whose pox-5 balance was already zeroed. Two cases:
;;   * REJECTED  -> the full `amount + max-fee` is unlocked back to the
;;                  requester. Fully reclaimable for the staker on-chain.
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
        (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" refund
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer refund tx-sender staker none
            ))
        )
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
        ;; must go through `reclaim-failed-withdrawal` so the staker is paid.
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
        (asserts! (<= new-fees MAX_BIPS) ERR_INVALID_FEES_BIPS)
        (print {
            topic: "update-fees",
            old-fees: (var-get fees-bips),
            new-fees: new-fees,
        })
        (var-set fees-bips new-fees)
        (ok true)
    )
)

;; Sweep orphaned sBTC fee-refund dust to a recipient.
;;
;; On an ACCEPTED withdrawal the sBTC protocol mints the unused fee budget
;; (`max-fee - actual-fee`) back to this contract. That dust cannot be
;; attributed to a specific staker on-chain (the sBTC registry does not expose
;; the actual fee paid), so it pools here; this admin-gated function sweeps it.
;;
;; The cap subtracts the fee accumulator (`earned-fees`), the outstanding
;; `withdrawal-liability`, and the pooled `unclaimed-staker-rewards` that
;; `claim-rewards` pulled in but no staker has claimed yet, so it can NEVER
;; sweep funds owed to a staker. A rejected-but-unreclaimed withdrawal's
;; `amount + max-fee` is present
;; in BOTH the sBTC balance (the protocol returned it here) and in
;; `withdrawal-liability` (the entry is still live), so the two cancel and the
;; refund stays untouchable -- whether or not anyone has called
;; `reclaim-failed-withdrawal` yet.
;;
;; The flip side: while a withdrawal is pending, or accepted but not yet retired
;; via `settle-accepted-withdrawal`, its full `amount + max-fee` suppresses the
;; sweepable amount. To recover the accept-case fee dust an admin must first
;; `settle-accepted-withdrawal` the accepted requests (and wait for any pending
;; ones to finalize).
(define-public (sweep-fee-refunds
        (amount uint)
        (recipient principal)
    )
    (let (
            (balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
            (reserved (+ (var-get earned-fees)
                (+ (var-get withdrawal-liability)
                    (var-get unclaimed-staker-rewards)
                )))
            (sweepable (if (>= balance reserved)
                (- balance reserved)
                u0
            ))
        )
        (try! (authorize-admin))
        (asserts! (<= amount sweepable) ERR_INVALID_SWEEP_AMOUNT)
        (print {
            topic: "sweep-fee-refunds",
            amount-sats: amount,
            recipient: recipient,
        })
        (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" amount
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer amount tx-sender recipient none
            ))
        )
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
        (try! (contract-call? .pox-5 grant-signer-key signer-key current-contract
            auth-id signer-sig
        ))
        (contract-call? .pox-5 register-signer signer-manager signer-key)
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
    (ok (asserts! (is-eq contract-caller .pox-5) ERR_UNAUTHORIZED_CALLER))
)

(define-read-only (is-admin (caller principal))
    (default-to false (map-get? admins caller))
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

(define-read-only (get-pox-addr (staker principal))
    (map-get? pox-addrs staker)
)

(define-read-only (get-withdrawal-request-staker (withdrawal-request uint))
    (map-get? withdrawal-requests withdrawal-request)
)

(define-read-only (check-pox-addr (pox-addr {
    version: (buff 1),
    hashbytes: (buff 32),
}))
    (let (
            (version (buff-to-uint-be (get version pox-addr)))
            (expected-len (if (<= version MAX_ADDRESS_VERSION_BUFF_20)
                u20
                u32
            ))
        )
        (ok (asserts!
            (and
                (<= version MAX_ADDRESS_VERSION)
                (is-eq (len (get hashbytes pox-addr)) expected-len)
                (is-eq (len (get version pox-addr)) u1)
            )
            ERR_INVALID_POX_ADDR
        ))
    )
)
