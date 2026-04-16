(use-trait pool-owner-trait .pox-5.pool-owner-trait)

(define-public (stake
        (amount-ustx uint)
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (start-burn-ht uint)
        (signer-sig (optional (buff 65)))
        (signer-key (buff 33))
        (max-amount uint)
        (auth-id uint)
        (num-cycles uint)
        (unlock-bytes (buff 683))
    )
    (contract-call? .pox-5 stake amount-ustx pox-addr start-burn-ht signer-sig signer-key max-amount auth-id num-cycles unlock-bytes)
)

(define-public (stake-pooled
        (pool-owner <pool-owner-trait>)
        (amount-ustx uint)
        (num-cycles uint)
        (unlock-bytes (buff 683))
        (start-burn-ht uint)
    )
    (contract-call? .pox-5 stake-pooled pool-owner amount-ustx num-cycles unlock-bytes start-burn-ht)
)

(define-public (stake-extend-pooled
        (pool-owner <pool-owner-trait>)
        (amount-ustx uint)
        (num-cycles uint)
        (unlock-bytes (buff 683))
    )
    (contract-call? .pox-5 stake-extend-pooled pool-owner amount-ustx num-cycles unlock-bytes)
)

(define-public (stake-extend
        (amount-ustx uint)
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        ;; #[allow(unused_binding)]
        (signer-sig (optional (buff 65)))
        (signer-key (buff 33))
        ;; #[allow(unused_binding)]
        (max-amount uint)
        ;; #[allow(unused_binding)]
        (auth-id uint)
        (num-cycles uint)
        (unlock-bytes (buff 683))
    )
    (contract-call? .pox-5 stake-extend amount-ustx pox-addr signer-sig signer-key max-amount auth-id num-cycles unlock-bytes)
)

(define-public (register-pool
        (pool-owner <pool-owner-trait>)
        (signer-key (buff 33))
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        ;; #[allow(unused_binding)]
        (signer-sig (buff 65))
        ;; #[allow(unused_binding)]
        (auth-id uint)
    )
    (contract-call? .pox-5 register-pool pool-owner signer-key pox-addr)
)

(define-public (stake-update-pooled
        (pool-owner <pool-owner-trait>)
        (amount-ustx-increase uint)
    )
    (contract-call? .pox-5 stake-update-pooled pool-owner amount-ustx-increase)
)

(define-public (stake-update
        (amount-ustx-increase uint)
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (signer-key (buff 33))
        (signer-sig (optional (buff 65)))
        (max-amount uint)
        (auth-id uint)
    )
    (contract-call? .pox-5 stake-update amount-ustx-increase pox-addr signer-key signer-sig max-amount auth-id)
)

(define-public (revoke-signer-grant
        (staker principal)
        (signer-key (buff 33))
    )
    (contract-call? .pox-5 revoke-signer-grant staker signer-key)
)