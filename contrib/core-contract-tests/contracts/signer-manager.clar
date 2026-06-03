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

;; Used to prevent fractional multiplication errors
;; during reward calculations
(define-constant PRECISION u1000000000000000000) ;; 1e18

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

(define-map rewards-per-token-for-cycle
    {
        index: uint,
        is-bond: bool,
    }
    uint
)

(define-map staker-rewards-per-token-settled-for-cycle
    {
        is-bond: bool,
        index: uint,
        staker: principal,
    }
    uint
)

;; Represents pending, but unclaimed rewards for a staker
(define-map staker-unclaimed-rewards-for-cycle
    {
        is-bond: bool,
        index: uint,
        staker: principal,
    }
    uint
)

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

;; Handling rewards checkpointing for a staker
(define-public (checkpoint-staker
        (staker principal)
        (first-index uint)
        (num-indexes uint)
        (is-bond bool)
    )
    (begin
        (try! (fold checkpoint-staker-for-index
            (unwrap-panic (slice?
                (list
                    u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15
                    u16 u17 u18 u19 u20 u21 u22 u23 u24 u25 u26 u27 u28 u29
                    u30 u31 u32 u33 u34 u35 u36 u37 u38 u39 u40 u41 u42 u43
                    u44 u45 u46 u47 u48 u49 u50 u51 u52 u53 u54 u55 u56 u57
                    u58 u59 u60 u61 u62 u63 u64 u65 u66 u67 u68 u69 u70 u71
                    u72 u73 u74 u75 u76 u77 u78 u79 u80 u81 u82 u83 u84 u85
                    u86 u87 u88 u89 u90 u91 u92 u93 u94 u95
                )
                u0 num-indexes
            ))
            (ok {
                staker: staker,
                first-index: first-index,
                is-bond: is-bond,
            })
        ))
        (ok true)
    )
)

(define-private (checkpoint-staker-for-index
        (index-offset uint)
        (acc-res (response {
            staker: principal,
            first-index: uint,
            is-bond: bool,
        }
            uint
        ))
    )
    (let (
            (acc (try! acc-res))
            (staker (get staker acc))
            (index (+ (get first-index acc) index-offset))
        )
        (settle-staker-rewards staker (get is-bond acc) index)
        (ok acc)
    )
)

;; Persist staker rewards state. This will update the staker's `pending` balance,
;; as well as account for any newly earned fees by the contract.
(define-private (settle-staker-rewards
        (staker principal)
        (is-bond bool)
        (index uint)
    )
    (let (
            (earned-info (get-earned-staker-rewards staker is-bond index))
            (rewards-per-token (get-rewards-per-token-for-cycle is-bond index))
            (prev-fees (var-get earned-fees))
        )
        (map-set staker-unclaimed-rewards-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        }
            (get earned earned-info)
        )
        (var-set earned-fees (+ prev-fees (get fees earned-info)))
        (map-set staker-rewards-per-token-settled-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        }
            rewards-per-token
        )
        {
            earned: (get earned earned-info),
            fees: (get fees earned-info),
            rewards-per-token: rewards-per-token,
        }
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
    (let ((new-rewards-info (try! (contract-call? .pox-5 claim-rewards bond-periods reward-cycle))))
        (update-rewards-info
            (get rewards-per-token (get stx-rewards new-rewards-info)) false
            reward-cycle
        )
        (fold update-bond-rewards-info (get bond-rewards new-rewards-info) true)
        (ok new-rewards-info)
    )
)

;;; Staker rewards

;; Get the total amount of rewards earned since the last
;; rewards snapshot for this staker.
;;
;; `earned = ((shares * (rpt - rptPaid)) / PRECISION) * (1 - feeRate) + pending`.
;;
;; If fees are set, then they are deducted from the _newly earned_ rewards - not
;; previously pending rewards.
(define-read-only (get-earned-staker-rewards
        (staker principal)
        (is-bond bool)
        (index uint)
    )
    (let (
            (shares (contract-call? .pox-5 get-staker-shares-staked-for-cycle staker
                is-bond index current-contract
            ))
            (rpt-current (get-rewards-per-token-for-cycle is-bond index))
            (rpt-paid (get-staker-rewards-per-token-paid-for-cycle staker is-bond index))
            (pending (get-staker-unclaimed-rewards-for-cycle staker is-bond index))
            (newly-earned-before-fees (/ (* shares (- rpt-current rpt-paid)) PRECISION))
            (fees (/ (* newly-earned-before-fees (var-get fees-bips)) MAX_BIPS))
            (newly-earned (- newly-earned-before-fees fees))
        )
        {
            earned: (+ pending newly-earned),
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
            (rewards-info (settle-staker-rewards staker is-bond index))
            (earned (get earned rewards-info))
        )
        (asserts! (> earned u0) ERR_NO_CLAIMABLE_REWARDS)
        (map-set staker-unclaimed-rewards-for-cycle {
            staker: staker,
            is-bond: is-bond,
            index: index,
        }
            u0
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

(define-read-only (is-admin (caller principal))
    (default-to false (map-get? admins caller))
)

(define-private (update-rewards-info
        (rewards-per-share uint)
        (is-bond bool)
        (index uint)
    )
    (begin
        (map-set rewards-per-token-for-cycle {
            index: index,
            is-bond: is-bond,
        }
            rewards-per-share
        )
    )
)

(define-private (update-bond-rewards-info
        (bond-info {
            bond-index: uint,
            earned: uint,
            rewards-per-token: uint,
        })
        ;; #[allow(unused_binding)]
        (acc bool)
    )
    (map-set rewards-per-token-for-cycle {
        is-bond: true,
        index: (get bond-index bond-info),
    }
        (get rewards-per-token bond-info)
    )
)

(define-read-only (get-rewards-per-token-for-cycle
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? rewards-per-token-for-cycle {
            index: index,
            is-bond: is-bond,
        })
    )
)

(define-read-only (get-staker-rewards-per-token-paid-for-cycle
        (staker principal)
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? staker-rewards-per-token-settled-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        })
    )
)

(define-read-only (get-staker-unclaimed-rewards-for-cycle
        (staker principal)
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? staker-unclaimed-rewards-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        })
    )
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
