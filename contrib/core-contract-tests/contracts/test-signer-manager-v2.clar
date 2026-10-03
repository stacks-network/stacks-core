;; A minimal successor to `signer-manager-v1`, used by the upgrade tests.

(define-constant MAX_BIPS u10000)
(define-constant FEE_BIPS u1000)

(define-map claimed-cycles
    uint
    bool
)

(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (begin
        (map-set claimed-cycles reward-cycle true)
        (contract-call? .signer-manager-core claim-rewards bond-periods
            reward-cycle
        )
    )
)

(define-public (settle-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (gross (try! (contract-call? .signer-manager-core settle-staker-rewards staker
                reward-cycle bond-index
            )))
            (fee (/ (* gross (fee-bips-for-cycle reward-cycle bond-index)) MAX_BIPS))
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

(define-public (payout (staker principal))
    (contract-call? .signer-manager-core payout staker
        (contract-call? .signer-manager-core get-pending-payout staker)
    )
)

(define-public (reclaim-failed-withdrawal (request-id uint))
    (contract-call? .signer-manager-core reclaim-failed-withdrawal request-id)
)

;; Cycles v1 pulled in keep v1's snapshotted fee.
(define-read-only (fee-bips-for-cycle
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (if (default-to false (map-get? claimed-cycles reward-cycle))
        FEE_BIPS
        (contract-call? .signer-manager-v1 get-fee-bips-for-cycle reward-cycle
            bond-index
        )
    )
)
