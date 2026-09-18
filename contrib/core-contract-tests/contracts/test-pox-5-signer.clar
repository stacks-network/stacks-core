(impl-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)
(use-trait signer-manager-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)

(define-constant ERR_NO_CLAIMABLE_REWARDS (err u1001))

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
        (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 grant-signer-key signer-key current-contract
            auth-id signer-sig
        ))
        (try! (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-signer signer-manager signer-key))
    )
)

(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (contract-call? 'ST000000000000000000002AMW42H.pox-5 claim-rewards bond-periods reward-cycle)
)

;; Get the total amount of rewards earned since the last
;; rewards snapshot for this staker.
(define-read-only (get-earned-staker-rewards
        (staker principal)
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (contract-call? 'ST000000000000000000002AMW42H.pox-5 get-earned-staker-rewards current-contract
        reward-cycle bond-index staker
    )
)

(define-public (claim-staker-rewards
        (reward-cycle uint)
        (bond-index (optional uint))
    )
    (let (
            (staker tx-sender)
            (rewards-info (unwrap-panic (contract-call? 'ST000000000000000000002AMW42H.pox-5 claim-staker-rewards-for-signer staker
                reward-cycle bond-index
            )))
            (earned (get earned rewards-info))
        )
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
        (asserts! (> earned u0) ERR_NO_CLAIMABLE_REWARDS)
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
