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
;; A pox-5 callback (validate-stake!, checkpoint-staker) was invoked by a
;; principal other than the pox-5 contract.
(define-constant ERR_UNAUTHORIZED_CALLER (err u1006))

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
    (as-contract? ()
        (try! (contract-call? .pox-5 claim-rewards bond-periods reward-cycle))
    )
)

;;; Staker rewards

;; Get the total amount of rewards earned since the last
;; rewards snapshot for this staker. Note that this does
;; NOT account for fees.
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
        (as-contract? ()
            (try! (contract-call? .pox-5 grant-signer-key signer-key current-contract
                auth-id signer-sig
            ))
            (try! (contract-call? .pox-5 register-signer signer-manager signer-key))
        )
    )
)

(define-private (authorize-admin)
    (ok (asserts! (and (is-eq contract-caller tx-sender) (is-admin tx-sender))
        ERR_UNAUTHORIZED_ADMIN
    ))
)

;; Ensure that the immediate caller is the pox-5 contract. The trait callbacks
;; (validate-stake!, checkpoint-staker) write per-staker state keyed by the
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
