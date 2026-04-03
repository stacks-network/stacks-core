;; The caller is already staked
(define-constant ERR_ALREADY_STAKED (err u1))
;; The caller is not staked
(define-constant ERR_NOT_STAKED (err u2))
;; The caller does not have sufficient STX to stake
(define-constant ERR_INSUFFICIENT_FUNDS (err u4))
;; The `start-burn-ht` is not valid - it must be in the next reward cycle
(define-constant ERR_INVALID_START_BURN_HEIGHT (err u8))
;; The `num-cycles` provided is invalid - it must be less than MAX_NUM_CYCLES
(define-constant ERR_INVALID_NUM_CYCLES (err u9))
;; The stacker tried to call `stake-extend` but not during their last cycle
(define-constant ERR_CANNOT_EXTEND (err u10))
(define-constant ERR_INVALID_AMOUNT (err u11))
(define-constant ERR_INVALID_POX_ADDRESS (err u13))
(define-constant ERR_POOL_NOT_FOUND (err u14))
;; The signer key grant has already been used
(define-constant ERR_SIGNER_KEY_GRANT_USED (err u15))
(define-constant ERR_INVALID_SIGNATURE_RECOVER (err u16))
(define-constant ERR_INVALID_SIGNATURE_PUBKEY (err u17))
(define-constant ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH (err u19))
(define-constant ERR_SIGNER_AUTH_USED (err u20))
(define-constant ERR_SIGNER_KEY_GRANT_NOT_FOUND (err u21))
(define-constant ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH (err u22))
(define-constant ERR_NOT_ALLOWED (err u23))

(define-trait pool-owner-trait (
    (validate-stake!
        ;; caller, amount-ustx, num-cycles, unlock-bytes
        (principal uint uint (buff 683))
        (response bool uint)
    )
    (validate-management!
        ;; caller, signer-key, pox-addr
        (principal (buff 33) {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (response bool uint)
    )
))

;; Values for stacks address versions
;; #[allow(unused_const)]
(define-constant STACKS_ADDR_VERSION_MAINNET 0x16)
;; #[allow(unused_const)]
(define-constant STACKS_ADDR_VERSION_TESTNET 0x1a)

;; Maximum number of cycles you can stake for
(define-constant MAX_NUM_CYCLES u24)

;; Minimum amount of uSTX you can stake
(define-constant MIN_STACKING_AMOUNT u100000000) ;; 100 STX

;; SIP18 message prefix
(define-constant SIP018_MSG_PREFIX 0x534950303138)

;; SIP018 domain
(define-constant POX_5_SIGNER_DOMAIN {
    name: "pox-5-signer",
    version: "1.0.0",
    chain-id: chain-id,
})

;; Keep these constants in lock-step with the address version buffs above
;; Maximum value of an address version as a uint
(define-constant MAX_ADDRESS_VERSION u6)
;; Maximum value of an address version that has a 20-byte hashbytes
;; (0x00, 0x01, 0x02, 0x03, and 0x04 have 20-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_20 u4)
;; Maximum value of an address version that has a 32-byte hashbytes
;; (0x05 and 0x06 have 32-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_32 u6)

;; Default length of the PoX registration window, in burnchain blocks.
(define-constant PREPARE_CYCLE_LENGTH (if is-in-mainnet
    u100
    u50
))

;; Default length of the PoX reward cycle, in burnchain blocks.
(define-constant REWARD_CYCLE_LENGTH (if is-in-mainnet
    u2100
    u1050
))

;; Data vars that store a copy of the burnchain configuration.
;; Implemented as data-vars, so that different configurations can be
;; used in e.g. test harnesses.
;; #[allow(unused_data_var)]
(define-data-var pox-prepare-cycle-length uint PREPARE_CYCLE_LENGTH)
(define-data-var pox-reward-cycle-length uint REWARD_CYCLE_LENGTH)
(define-data-var first-burnchain-block-height uint u0)
(define-data-var configured bool false)
;; #[allow(unused_data_var)]
(define-data-var first-pox-5-reward-cycle uint u0)

;; This function can only be called once, when it boots up
(define-public (set-burnchain-parameters
        (first-burn-height uint)
        (prepare-cycle-length uint)
        (reward-cycle-length uint)
        (begin-pox5-reward-cycle uint)
    )
    (begin
        (unwrap-panic (if (var-get configured)
            (err false)
            (ok true)
        ))
        (var-set first-burnchain-block-height first-burn-height)
        (var-set pox-prepare-cycle-length prepare-cycle-length)
        (var-set pox-reward-cycle-length reward-cycle-length)
        (var-set first-pox-5-reward-cycle begin-pox5-reward-cycle)
        (var-set configured true)
        (ok true)
    )
)

;; Users can stake to a pool, where the pool owner
;; (which is the key of this map) is able to manage
;; the signer key and pox address for the pool.
(define-map pools
    principal
    {
        signer-key: (buff 33),
        pox-addr: {
            version: (buff 1),
            hashbytes: (buff 32),
        },
    }
)

(define-map staking-state
    principal
    {
        num-cycles: uint,
        unlock-bytes: (buff 683),
        amount-ustx: uint,
        first-reward-cycle: uint,
        pool-or-solo-info: (response principal {
            pox-addr: {
                version: (buff 1),
                hashbytes: (buff 32),
            },
            signer-key: (buff 33),
        }),
    }
)

(define-map signer-key-grants
    {
        signer-key: (buff 33),
        staker: principal,
    }
    (optional {
        version: (buff 1),
        hashbytes: (buff 32),
    })
)

(define-map used-signer-key-grants
    {
        signer-key: (buff 33),
        staker: principal,
        auth-id: uint,
    }
    bool
)

;; State for tracking used signer key authorizations. This prevents re-use
;; of the same signature or pre-set authorization for multiple transactions.
;; Refer to the `signer-key-authorizations` map for the documentation on these fields
(define-map used-signer-key-authorizations
    {
        signer-key: (buff 33),
        reward-cycle: uint,
        period: uint,
        topic: (string-ascii 14),
        pox-addr: {
            version: (buff 1),
            hashbytes: (buff 32),
        },
        auth-id: uint,
        max-amount: uint,
    }
    bool ;; Whether the field has been used or not
)

;; What's the reward cycle number of the burnchain block height?
;; Will runtime-abort if height is less than the first burnchain block (this is intentional)
(define-read-only (burn-height-to-reward-cycle (height uint))
    (/ (- height (var-get first-burnchain-block-height))
        (var-get pox-reward-cycle-length)
    )
)

;; What's the block height at the start of a given reward cycle?
(define-read-only (reward-cycle-to-burn-height (cycle uint))
    (+ (var-get first-burnchain-block-height)
        (* cycle (var-get pox-reward-cycle-length))
    )
)

;; Get the L1 unlock height for a given reward cycle.
;; This is equal to exactly halfway through the provided cycle.
(define-read-only (reward-cycle-to-unlock-height (cycle uint))
    (+ (reward-cycle-to-burn-height cycle)
        (/ (var-get pox-reward-cycle-length) u2)
    )
)

;; What's the current PoX reward cycle?
(define-read-only (current-pox-reward-cycle)
    (burn-height-to-reward-cycle burn-block-height)
)

;; Get the _current_ PoX staking principal information.  If the information
;; is expired, or if there's never been such a staker, then returns none.
(define-read-only (get-staker-info (staker principal))
    (match (map-get? staking-state staker)
        staking-info
        (if (<=
                (+ (get first-reward-cycle staking-info)
                    (get num-cycles staking-info)
                )
                (current-pox-reward-cycle)
            )
            ;; present, but lock has expired
            none
            ;; present, and lock has not expired
            (some staking-info)
        )
        ;; no state at all
        none
    )
)

(define-read-only (get-pool-info (owner principal))
    (map-get? pools owner)
)

;; TODO
;; #[allow(unused_binding)]
(define-read-only (get-total-ustx-stacked (reward-cycle uint))
    u0
)

(define-read-only (get-pox-info)
    (ok {
        min-amount-ustx: MIN_STACKING_AMOUNT,
        reward-cycle-id: (current-pox-reward-cycle),
        prepare-cycle-length: (var-get pox-prepare-cycle-length),
        first-burnchain-block-height: (var-get first-burnchain-block-height),
        reward-cycle-length: (var-get pox-reward-cycle-length),
        total-liquid-supply-ustx: stx-liquid-supply,
    })
)

;;; Public functions

(define-public (stake-pooled
        (pool-owner <pool-owner-trait>)
        (amount-ustx uint)
        (num-cycles uint)
        (unlock-bytes (buff 683))
        (start-burn-ht uint)
    )
    (let ((owner (contract-of pool-owner)))
        (asserts! (is-some (get-pool-info owner)) ERR_POOL_NOT_FOUND)
        (try! (contract-call? pool-owner validate-stake! tx-sender amount-ustx
            num-cycles unlock-bytes
        ))
        (inner-stake amount-ustx num-cycles unlock-bytes start-burn-ht (ok owner))
    )
)

;; #[allow(unnecessary_public)]
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
    ;; this stacker's first reward cycle is the _next_ reward cycle
    (begin
        ;;  pox-addr must be valid
        (try! (check-pox-addr pox-addr))

        (try! (validate-signer-key-usage pox-addr (current-pox-reward-cycle) "stake"
            num-cycles signer-sig signer-key amount-ustx max-amount auth-id
            tx-sender
        ))

        (inner-stake amount-ustx num-cycles unlock-bytes start-burn-ht
            (err {
                pox-addr: pox-addr,
                signer-key: signer-key,
            })
        )
    )
)

(define-private (inner-stake
        (amount-ustx uint)
        (num-cycles uint)
        (unlock-bytes (buff 683))
        (start-burn-ht uint)
        (pool-or-solo-info (response principal {
            pox-addr: {
                version: (buff 1),
                hashbytes: (buff 32),
            },
            signer-key: (buff 33),
        }))
    )
    (let (
            (current-cycle (current-pox-reward-cycle))
            (first-reward-cycle (+ u1 current-cycle))
            (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht)))
            (unlock-cycle (+ current-cycle num-cycles))
            (unlock-burn-height (reward-cycle-to-unlock-height unlock-cycle))
        )
        ;; the start-burn-ht must result in the next reward cycle, do not allow stackers
        ;;  to "post-date" their `stack-stx` transaction
        (asserts! (is-eq first-reward-cycle specified-reward-cycle)
            ERR_INVALID_START_BURN_HEIGHT
        )

        ;;  amount must be valid
        (asserts! (>= amount-ustx MIN_STACKING_AMOUNT) ERR_INVALID_AMOUNT)

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;;;;  must be called directly by the tx-sender or by an allowed contract-caller
        ;; (asserts! (check-caller-allowed) (err ERR_STACKING_PERMISSION_DENIED))

        ;;;;  tx-sender principal must not be stacking
        (asserts! (is-none (get-staker-info tx-sender)) ERR_ALREADY_STAKED)

        ;;;;  the Stacker must have sufficient unlocked funds
        (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
            ERR_INSUFFICIENT_FUNDS
        )

        (try! (add-staker-to-reward-cycles tx-sender first-reward-cycle num-cycles))

        (map-set staking-state tx-sender {
            amount-ustx: amount-ustx,
            unlock-bytes: unlock-bytes,
            first-reward-cycle: first-reward-cycle,
            num-cycles: num-cycles,
            pool-or-solo-info: pool-or-solo-info,
        })

        (ok {
            stacker: tx-sender,
            unlock-burn-height: unlock-burn-height,
            unlock-bytes: unlock-bytes,
            amount-ustx: amount-ustx,
            unlock-cycle: unlock-cycle,
            num-cycles: num-cycles,
            pool-or-solo-info: pool-or-solo-info,
        })
    )
)

(define-public (stake-extend-pooled
        (pool-owner <pool-owner-trait>)
        (amount-ustx uint)
        (num-cycles uint)
        (unlock-bytes (buff 683))
    )
    (let ((owner (contract-of pool-owner)))
        (asserts! (is-some (get-pool-info owner)) ERR_POOL_NOT_FOUND)
        (try! (contract-call? pool-owner validate-stake! tx-sender amount-ustx
            num-cycles unlock-bytes
        ))
        (inner-stake-extend amount-ustx num-cycles unlock-bytes (ok owner))
    )
)

;; #[allow(unnecessary_public)]
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
    (begin
        (try! (validate-signer-key-usage pox-addr (current-pox-reward-cycle)
            "stake-extend" num-cycles signer-sig signer-key amount-ustx
            max-amount auth-id tx-sender
        ))

        ;;  pox-addr must be valid
        (try! (check-pox-addr pox-addr))

        (inner-stake-extend amount-ustx num-cycles unlock-bytes
            (err {
                pox-addr: pox-addr,
                signer-key: signer-key,
            })
        )
    )
)

(define-private (inner-stake-extend
        (amount-ustx uint)
        (num-cycles uint)
        (unlock-bytes (buff 683))
        (pool-or-solo-info (response principal {
            pox-addr: {
                version: (buff 1),
                hashbytes: (buff 32),
            },
            signer-key: (buff 33),
        }))
    )
    (let (
            (current-stacker-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKED))
            (prev-unlock-cycle (-
                (+ (get first-reward-cycle current-stacker-info)
                    (get num-cycles current-stacker-info)
                )
                u1
            ))
            (current-cycle (current-pox-reward-cycle))
            (unlock-cycle (+ current-cycle num-cycles))
            (unlock-burn-height (reward-cycle-to-unlock-height unlock-cycle))
            (account-info (stx-account tx-sender))
        )
        (asserts! (is-eq prev-unlock-cycle current-cycle) ERR_CANNOT_EXTEND)

        (try! (add-staker-to-reward-cycles tx-sender (+ current-cycle u1) num-cycles))

        ;; The caller has locked STX - we need to ensure that their locked + unlocked balance
        ;; is sufficient
        (asserts!
            (>= (+ (get locked account-info) (get unlocked account-info))
                amount-ustx
            )
            ERR_INSUFFICIENT_FUNDS
        )

        ;;  amount must be valid
        (asserts! (> amount-ustx u0) ERR_INVALID_AMOUNT)

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        (map-set staking-state tx-sender {
            amount-ustx: amount-ustx,
            first-reward-cycle: (+ current-cycle u1),
            num-cycles: num-cycles,
            unlock-bytes: unlock-bytes,
            pool-or-solo-info: pool-or-solo-info,
        })

        (ok {
            stacker: tx-sender,
            unlock-burn-height: unlock-burn-height,
            unlock-bytes: unlock-bytes,
            amount-ustx: amount-ustx,
            unlock-cycle: unlock-cycle,
            num-cycles: num-cycles,
            pool-or-solo-info: pool-or-solo-info,
        })
    )
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
    (let ((owner (contract-of pool-owner)))
        (try! (verify-signer-key-grant tx-sender signer-key pox-addr))

        (try! (check-pox-addr pox-addr))

        (try! (contract-call? pool-owner validate-management! tx-sender signer-key
            pox-addr
        ))

        (map-set pools owner {
            signer-key: signer-key,
            pox-addr: pox-addr,
        })
        (ok {
            owner: owner,
            signer-key: signer-key,
            pox-addr: pox-addr,
        })
    )
)

;; Allow a user to update their staked STX amount or pool while they are staked.
(define-public (stake-update-pooled
        (pool-owner <pool-owner-trait>)
        (amount-ustx-increase uint)
    )
    (let (
            (owner (contract-of pool-owner))
            (staker-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKED))
        )
        (asserts! (is-some (get-pool-info owner)) ERR_POOL_NOT_FOUND)
        (try! (contract-call? pool-owner validate-stake! tx-sender
            (+ (get amount-ustx staker-info) amount-ustx-increase)
            (get num-cycles staker-info) (get unlock-bytes staker-info)
        ))
        (inner-stake-update amount-ustx-increase (ok owner))
    )
)

;; Allow a user to update their staked STX amount, signer key,
;; and/or PoX address while they are staked.
;;
;; #[allow(unnecessary_public)]
(define-public (stake-update
        (amount-ustx-increase uint)
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (signer-key (buff 33))
        ;; #[allow(unused_binding)]
        (signer-sig (optional (buff 65)))
        ;; #[allow(unused_binding)]
        (max-amount uint)
        ;; #[allow(unused_binding)]
        (auth-id uint)
    )
    (begin
        ;;  pox-addr must be valid
        (try! (check-pox-addr pox-addr))

        (let (
                (stake-update-result (try! (inner-stake-update amount-ustx-increase
                    (err {
                        pox-addr: pox-addr,
                        signer-key: signer-key,
                    })
                )))
                (cycles-remaining (- (get unlock-cycle stake-update-result)
                    (current-pox-reward-cycle)
                ))
            )
            (try! (validate-signer-key-usage pox-addr (current-pox-reward-cycle)
                "stake-update" cycles-remaining signer-sig signer-key
                amount-ustx-increase max-amount auth-id tx-sender
            ))
            (ok stake-update-result)
        )
    )
)

(define-private (inner-stake-update
        (amount-ustx-increase uint)
        (pool-or-solo-info (response principal {
            pox-addr: {
                version: (buff 1),
                hashbytes: (buff 32),
            },
            signer-key: (buff 33),
        }))
    )
    (let (
            (current-stacker-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKED))
            (new-amount-ustx (+ (get amount-ustx current-stacker-info) amount-ustx-increase))
            (unlock-cycle (-
                (+ (get first-reward-cycle current-stacker-info)
                    (get num-cycles current-stacker-info)
                )
                u1
            ))
        )
        ;; assert that the amount of STX to increase is greater than 0
        (asserts! (> amount-ustx-increase u0) ERR_INVALID_AMOUNT)

        ;; assert that the staker has sufficient STX to increase their stake
        (asserts! (>= (stx-get-balance tx-sender) amount-ustx-increase)
            ERR_INSUFFICIENT_FUNDS
        )

        (map-set staking-state tx-sender {
            amount-ustx: new-amount-ustx,
            first-reward-cycle: (get first-reward-cycle current-stacker-info),
            num-cycles: (get num-cycles current-stacker-info),
            unlock-bytes: (get unlock-bytes current-stacker-info),
            pool-or-solo-info: pool-or-solo-info,
        })

        (ok {
            stacker: tx-sender,
            unlock-burn-height: (reward-cycle-to-unlock-height unlock-cycle),
            unlock-bytes: (get unlock-bytes current-stacker-info),
            amount-ustx: new-amount-ustx,
            unlock-cycle: unlock-cycle,
            num-cycles: (get num-cycles current-stacker-info),
            pool-or-solo-info: pool-or-solo-info,
        })
    )
)

;;; Signer key authorization functions

(define-public (grant-signer-key
        (signer-key (buff 33))
        (staker principal)
        (pox-addr (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }))
        (auth-id uint)
        (signer-sig (buff 65))
    )
    (begin
        (asserts!
            (is-none (map-get? used-signer-key-grants {
                signer-key: signer-key,
                staker: staker,
                auth-id: auth-id,
            }))
            ERR_SIGNER_KEY_GRANT_USED
        )

        (asserts!
            (is-eq
                (unwrap!
                    (secp256k1-recover?
                        (get-signer-grant-message-hash staker pox-addr auth-id)
                        signer-sig
                    )
                    ERR_INVALID_SIGNATURE_RECOVER
                )
                signer-key
            )
            ERR_INVALID_SIGNATURE_PUBKEY
        )

        (asserts!
            (map-insert used-signer-key-grants {
                signer-key: signer-key,
                staker: staker,
                auth-id: auth-id,
            }
                true
            )
            ERR_SIGNER_KEY_GRANT_USED
        )

        (map-set signer-key-grants {
            signer-key: signer-key,
            staker: staker,
        }
            pox-addr
        )

        (ok true)
    )
)

;; Revoke a signer key grant for a staker. Only the Stacks principal
;; associated with `signer-key` can call this function.
;;
;; Returns a boolean indicating whether the signer key grant existed.
(define-public (revoke-signer-grant
        (staker principal)
        (signer-key (buff 33))
    )
    (begin
        ;; Validate that `tx-sender` has the same pubkey hash as `signer-key`
        (asserts!
            (is-eq
                (unwrap-panic (principal-construct?
                    (if is-in-mainnet
                        STACKS_ADDR_VERSION_MAINNET
                        STACKS_ADDR_VERSION_TESTNET
                    )
                    (hash160 signer-key)
                ))
                tx-sender
            )
            ERR_NOT_ALLOWED
        )
        (ok (map-delete signer-key-grants {
            signer-key: signer-key,
            staker: staker,
        }))
    )
)

;; Generate a message hash for validating a signer key.
;; The message hash follows SIP018 for signing structured data. The structured data
;; is the tuple `{ pox-addr: { version, hashbytes }, reward-cycle, auth-id, max-amount, topic, period }`.
;; The domain is [POX_5_SIGNER_DOMAIN].
(define-read-only (get-signer-key-message-hash
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (reward-cycle uint)
        (topic (string-ascii 14))
        (period uint)
        (max-amount uint)
        (auth-id uint)
    )
    (sha256 (concat SIP018_MSG_PREFIX
        (concat (sha256 (unwrap-panic (to-consensus-buff? POX_5_SIGNER_DOMAIN)))
            (sha256 (unwrap-panic (to-consensus-buff? {
                pox-addr: pox-addr,
                reward-cycle: reward-cycle,
                topic: topic,
                period: period,
                auth-id: auth-id,
                max-amount: max-amount,
            })))
        )))
)

;; Construct the message hash for validating a signer key grant. Unlike [get-signer-key-message-hash],
;; this message hash does not include `max-amount`, `period`, or `reward-cycle`. The topic is always `"grant-authorization"`.
;; The `pox-addr` field is optional. When `none`, it means the signer key can be used for any PoX address.
(define-read-only (get-signer-grant-message-hash
        (staker principal)
        (pox-addr (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }))
        (auth-id uint)
    )
    (sha256 (concat SIP018_MSG_PREFIX
        (concat (sha256 (unwrap-panic (to-consensus-buff? POX_5_SIGNER_DOMAIN)))
            (sha256 (unwrap-panic (to-consensus-buff? {
                topic: "grant-authorization",
                staker: staker,
                pox-addr: pox-addr,
                auth-id: auth-id,
            })))
        )))
)

;; Verify a signature from the signing key for this specific stacker.
;; See `get-signer-key-message-hash` for details on the message hash.
;;
;; Note that `reward-cycle` corresponds to the _current_ reward cycle,
;; when used with `stack-stx` and `stack-extend`. Both the reward cycle and
;; the lock period are inflexible, which means that the stacker must confirm their transaction
;; during the exact reward cycle and with the exact period that the signature or authorization was
;; generated for.
;;
;; The `amount` field is checked to ensure it is not larger than `max-amount`, which is
;; a field in the authorization. `auth-id` is a random uint to prevent authorization
;; replays.
;;
;; This function does not verify the payload of the authorization. The caller of
;; this function must ensure that the payload (reward cycle, period, topic, and pox-addr)
;; are valid according to the caller function's requirements.
;;
;; When `signer-sig` is present, the public key is recovered from the signature
;; and compared to `signer-key`. If `signer-sig` is `none`, the function verifies that an authorization was previously
;; added for this key.
;;
;; This function checks to ensure that the authorization hasn't been used yet, but it
;; does _not_ store the authorization as used. The function `consume-signer-key-authorization`
;; handles that, and this read-only function is exposed for client-side verification.
(define-read-only (verify-signer-key-sig
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (reward-cycle uint)
        (topic (string-ascii 14))
        (period uint)
        (signer-sig (buff 65))
        (signer-key (buff 33))
        (amount uint)
        (max-amount uint)
        (auth-id uint)
    )
    (begin
        ;; Validate that amount is less than or equal to `max-amount`
        (asserts! (>= max-amount amount) ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH)
        (asserts!
            (is-none (map-get? used-signer-key-authorizations {
                signer-key: signer-key,
                reward-cycle: reward-cycle,
                topic: topic,
                period: period,
                pox-addr: pox-addr,
                auth-id: auth-id,
                max-amount: max-amount,
            }))
            ERR_SIGNER_AUTH_USED
        )
        (ok (asserts!
            (is-eq
                (unwrap!
                    (secp256k1-recover?
                        (get-signer-key-message-hash pox-addr reward-cycle topic
                            period max-amount auth-id
                        )
                        signer-sig
                    )
                    ERR_INVALID_SIGNATURE_RECOVER
                )
                signer-key
            )
            ERR_INVALID_SIGNATURE_PUBKEY
        ))
    )
)

;; This function does two things:
;;
;; - Verify that a signer key is authorized to be used
;; - Updates the `used-signer-key-authorizations` map to prevent reuse
;;
;; This "wrapper" method around `verify-signer-key-sig` allows that function to remain
;; read-only, so that it can be used by clients as a sanity check before submitting a transaction.
(define-private (consume-signer-key-authorization
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (reward-cycle uint)
        (topic (string-ascii 14))
        (period uint)
        (signer-sig (buff 65))
        (signer-key (buff 33))
        (amount uint)
        (max-amount uint)
        (auth-id uint)
    )
    (begin
        ;; verify the authorization
        (try! (verify-signer-key-sig pox-addr reward-cycle topic period signer-sig
            signer-key amount max-amount auth-id
        ))
        ;; update the `used-signer-key-authorizations` map
        (asserts!
            (map-insert used-signer-key-authorizations {
                signer-key: signer-key,
                reward-cycle: reward-cycle,
                topic: topic,
                period: period,
                pox-addr: pox-addr,
                auth-id: auth-id,
                max-amount: max-amount,
            }
                true
            )
            ERR_SIGNER_AUTH_USED
        )
        (ok true)
    )
)

;; if signer-sig-opt is present, verify the signature. Otherwise,
;; verify that a grant was previously added for this key.
(define-private (validate-signer-key-usage
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (reward-cycle uint)
        (topic (string-ascii 14))
        (period uint)
        (signer-sig-opt (optional (buff 65)))
        (signer-key (buff 33))
        (amount uint)
        (max-amount uint)
        (auth-id uint)
        (staker principal)
    )
    (match signer-sig-opt
        signer-sig (consume-signer-key-authorization pox-addr reward-cycle topic period
            signer-sig signer-key amount max-amount auth-id
        )
        (verify-signer-key-grant staker signer-key pox-addr)
    )
)

(define-read-only (verify-signer-key-grant
        (staker principal)
        (signer-key (buff 33))
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
    )
    (ok (asserts!
        (match (unwrap!
            (map-get? signer-key-grants {
                signer-key: signer-key,
                staker: staker,
            })
            ERR_SIGNER_KEY_GRANT_NOT_FOUND
        )
            grant-pox-addr (is-eq grant-pox-addr pox-addr)
            true
        )
        ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH
    ))
)

;;; Validation helpers

(define-read-only (check-pox-lock-period (lock-period uint))
    (and
        (>= lock-period u1)
        (<= lock-period MAX_NUM_CYCLES)
    )
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
            )
            ERR_INVALID_POX_ADDRESS
        ))
    )
)

;; Is the address mode valid for a PoX address?
(define-read-only (check-pox-addr-version (version (buff 1)))
    (<= (buff-to-uint-be version) MAX_ADDRESS_VERSION)
)

;; Is this buffer the right length for the given PoX address?
(define-read-only (check-pox-addr-hashbytes
        (version (buff 1))
        (hashbytes (buff 32))
    )
    (if (<= (buff-to-uint-be version) MAX_ADDRESS_VERSION_BUFF_20)
        (is-eq (len hashbytes) u20)
        (if (<= (buff-to-uint-be version) MAX_ADDRESS_VERSION_BUFF_32)
            (is-eq (len hashbytes) u32)
            false
        )
    )
)

;;; Cycle-based Linked List functions

;; First item in the linked list of stakers
(define-map staker-set-ll-first-for-cycle
    uint
    principal
)
;; Last item in the linked list of stakers
(define-map staker-set-ll-last-for-cycle
    uint
    principal
)

;; Linked list of all stakers for a cycle
(define-map staker-set-ll-for-cycle
    {
        cycle: uint,
        staker: principal,
    }
    {
        prev: (optional principal),
        next: (optional principal),
    }
)

(define-read-only (get-staker-set-last-item-for-cycle (cycle uint))
    (map-get? staker-set-ll-last-for-cycle cycle)
)

(define-read-only (get-staker-set-first-item-for-cycle (cycle uint))
    (map-get? staker-set-ll-first-for-cycle cycle)
)

(define-read-only (get-staker-set-item-for-cycle
        (staker principal)
        (cycle uint)
    )
    (map-get? staker-set-ll-for-cycle {
        cycle: cycle,
        staker: staker,
    })
)

(define-read-only (get-staker-set-next-item-for-cycle
        (staker principal)
        (cycle uint)
    )
    (match (map-get? staker-set-ll-for-cycle {
        cycle: cycle,
        staker: staker,
    })
        item (get next item)
        none
    )
)

(define-read-only (get-staker-set-prev-item-for-cycle
        (staker principal)
        (cycle uint)
    )
    (match (map-get? staker-set-ll-for-cycle {
        cycle: cycle,
        staker: staker,
    })
        item (get prev item)
        none
    )
)

(define-read-only (staker-set-contains-for-cycle
        (staker principal)
        (cycle uint)
    )
    (is-some (map-get? staker-set-ll-for-cycle {
        cycle: cycle,
        staker: staker,
    }))
)

(define-private (add-staker-to-set-for-cycle
        (staker principal)
        (cycle uint)
    )
    (let ((last-item (map-get? staker-set-ll-last-for-cycle cycle)))
        ;; Todo: remove this and guard in a higher-level fn
        (asserts!
            (not (is-some (map-get? staker-set-ll-for-cycle {
                cycle: cycle,
                staker: staker,
            })))
            ERR_ALREADY_STAKED
        )

        (match last-item
            last-stacker (let ((last-node (unwrap-panic (map-get? staker-set-ll-for-cycle {
                    cycle: cycle,
                    staker: last-stacker,
                }))))
                (map-set staker-set-ll-for-cycle {
                    cycle: cycle,
                    staker: last-stacker,
                } {
                    prev: (get prev last-node),
                    next: (some staker),
                })
                (map-set staker-set-ll-for-cycle {
                    cycle: cycle,
                    staker: staker,
                } {
                    prev: (some last-stacker),
                    next: none,
                })
            )
            (begin
                ;; This is the first item
                (map-set staker-set-ll-for-cycle {
                    cycle: cycle,
                    staker: staker,
                } {
                    prev: none,
                    next: none,
                })
                (map-set staker-set-ll-first-for-cycle cycle staker)
            )
        )

        (map-set staker-set-ll-last-for-cycle cycle staker)
        (ok true)
    )
)

(define-private (add-staker-to-reward-cycles
        (staker principal)
        (first-reward-cycle uint)
        (num-cycles uint)
    )
    (let ((cycle-indexes (unwrap!
            (slice?
                (list
                    u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15
                    u16 u17 u18 u19 u20 u21 u22 u23
                )
                u0 num-cycles
            )
            ERR_INVALID_NUM_CYCLES
        )))
        (try! (fold add-staker-to-nth-reward-cycle cycle-indexes
            (ok {
                staker: staker,
                first-reward-cycle: first-reward-cycle,
            })
        ))
        (ok true)
    )
)

(define-private (add-staker-to-nth-reward-cycle
        (cycle-index uint)
        (params-resp (response {
            staker: principal,
            first-reward-cycle: uint,
        }
            uint
        ))
    )
    (let ((params (try! params-resp)))
        (try! (add-staker-to-set-for-cycle (get staker params)
            (+ (get first-reward-cycle params) cycle-index)
        ))
        (ok params)
    )
)
