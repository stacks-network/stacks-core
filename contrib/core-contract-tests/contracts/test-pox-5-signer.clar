(impl-trait .pox-5.signer-manager-trait)
(use-trait signer-manager-trait .pox-5.signer-manager-trait)

(define-constant ERR_NO_CLAIMABLE_REWARDS (err u1001))

;; Used to prevent fractional multiplication errors
;; during reward calculations
(define-constant PRECISION u1000000000000000000) ;; 1e18

;; default to allowing deployer to register as a pool
(define-data-var allowed-caller principal tx-sender)

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
        (amount-ustx uint)
        ;; #[allow(unused_binding)]
        (amount-sats uint)
        ;; #[allow(unused_binding)]
        (num-cycles uint)
        ;; #[allow(unused_binding)]
        (is-bond bool)
        ;; #[allow(unused_binding)]
        (signer-calldata (optional (buff 500)))
    )
    (ok true)
)

(define-public (update-allowed-caller (new-allowed-caller principal))
    (ok (var-set allowed-caller new-allowed-caller))
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
        (index uint)
        (is-bond bool)
    )
    ;; (let (
    ;;         (rewards-paid (get-staker-rewards-paid-per-token-for-cycle staker index is-bond))
    ;;         (rewards-per-share (get-rewards-per-token-for-cycle index is-bond))
    ;;         (shares-staked (contract-call? .pox-5 get-staker-shares-staked-for-cycle staker
    ;;             index is-bond current-contract
    ;;         ))
    ;;         (rewards-pending (- (/ (* shares-staked rewards-per-share) PRECISION) rewards-paid))
    ;;     )
    ;;     {
    ;;         rewards-paid: rewards-paid,
    ;;         rewards-pending: rewards-pending,
    ;;         shares-staked: shares-staked,
    ;;         rewards-per-share: rewards-per-share,
    ;;     }
    ;; )
    (let (
            (shares (contract-call? .pox-5 get-staker-shares-staked-for-cycle staker
                index is-bond current-contract
            ))
            (rpt-current (get-rewards-per-token-for-cycle index is-bond))
            (rpt-paid (get-staker-rewards-per-token-paid-for-cycle staker index is-bond))
            (pending (get-staker-pending-rewards-for-cycle staker index is-bond))
            (newly-earned (/ (* shares (- rpt-current rpt-paid)) PRECISION))
        )
        (+ pending newly-earned)
    )
)

(define-public (claim-staker-rewards
        (index uint)
        (is-bond bool)
    )
    (let (
            (staker tx-sender)
            (earned (get-earned-staker-rewards staker index is-bond))
            (rewards-per-token (get-rewards-per-token-for-cycle index is-bond))
        )
        (asserts! (> earned u0) ERR_NO_CLAIMABLE_REWARDS)
        (map-set staker-rewards-paid-per-token-for-cycle {
            index: index,
            is-bond: is-bond,
            staker: staker,
        } rewards-per-token)
        (map-set staker-pending-rewards-for-cycle {
            staker: staker,
            is-bond: is-bond,
            index: index,
        } u0)
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
        (index uint)
        (is-bond bool)
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
        (index uint)
        (is-bond bool)
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
        (index uint)
        (is-bond bool)
    )
    (default-to u0
        (map-get? staker-pending-rewards-for-cycle {
            staker: staker,
            index: index,
            is-bond: is-bond,
        })
    )
)
