(impl-trait .pox-5.signer-manager-trait)
(use-trait signer-manager-trait .pox-5.signer-manager-trait)

(define-constant ERR_NO_CLAIMABLE_REWARDS (err u1001))

;; Used to prevent fractional multiplication errors
;; during reward calculations
(define-constant PRECISION u1000000000000000000) ;; 1e18

(define-map rewards-per-token-for-cycle
    {
        index: uint,
        is-bond: bool,
    }
    uint
)

(define-map staker-rewards-paid-per-token-for-cycle
    {
        is-bond: bool,
        index: uint,
        staker: principal,
    }
    uint
)

;; Represents pending, but unclaimed rewards for a staker
(define-map staker-pending-rewards-for-cycle
    {
        is-bond: bool,
        index: uint,
        staker: principal,
    }
    uint
)

;; #[allow(unnecessary_public)]
(define-public (validate-stake!
        ;; #[allow(unused_binding)]
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
        ;; #[allow(unused_binding)]
        (signer-calldata (optional (buff 500)))
    )
    (ok true)
)

(define-public (register-self
        (signer-manager <signer-manager-trait>)
        (signer-key (buff 33))
        (auth-id uint)
        (signer-sig (buff 65))
    )
    (as-contract? ()
        (try! (contract-call? .pox-5 grant-signer-key signer-key current-contract
            auth-id signer-sig
        ))
        (try! (contract-call? .pox-5 register-signer signer-manager signer-key))
    )
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
        (crystallize-staker-rewards staker (get is-bond acc) index)
        (ok acc)
    )
)

(define-private (crystallize-staker-rewards
        (staker principal)
        (is-bond bool)
        (index uint)
    )
    (let (
            (earned (get-earned-staker-rewards staker is-bond index))
            (rewards-per-token (get-rewards-per-token-for-cycle is-bond index))
        )
        (map-set staker-pending-rewards-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        }
            earned
        )
        (map-set staker-rewards-paid-per-token-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        }
            rewards-per-token
        )
        {
            earned: earned,
            rewards-per-token: rewards-per-token,
        }
    )
)

(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (let ((new-rewards-info (try! (as-contract? ()
            (try! (contract-call? .pox-5 claim-rewards bond-periods reward-cycle))
        ))))
        (update-rewards-info
            (get rewards-per-token (get stx-rewards new-rewards-info)) false
            reward-cycle
        )
        (fold update-bond-rewards-info (get bond-rewards new-rewards-info) true)
        (ok new-rewards-info)
    )
)

;; Get the total amount of rewards earned since the last
;; rewards snapshot for this staker.
;;
;; `earned = (shares * (rpt - rptPaid)) / PRECISION + pending`
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
            (pending (get-staker-pending-rewards-for-cycle staker is-bond index))
            (newly-earned (/ (* shares (- rpt-current rpt-paid)) PRECISION))
        )
        (+ pending newly-earned)
    )
)

(define-public (claim-staker-rewards
        (is-bond bool)
        (index uint)
    )
    (let (
            (staker tx-sender)
            (rewards-info (crystallize-staker-rewards staker is-bond index))
            (earned (get earned rewards-info))
        )
        (asserts! (> earned u0) ERR_NO_CLAIMABLE_REWARDS)
        (map-set staker-pending-rewards-for-cycle {
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
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer earned tx-sender staker none
            ))
        ))
        (ok earned)
    )
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
        (map-get? staker-rewards-paid-per-token-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        })
    )
)

(define-read-only (get-staker-pending-rewards-for-cycle
        (staker principal)
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? staker-pending-rewards-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        })
    )
)
