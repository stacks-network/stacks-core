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

(use-trait pool-owner-trait .pox-5-pool-owner-trait.pool-owner-trait)

;; Values for stacks address versions
;; #[allow(unused_const)]
(define-constant STACKS_ADDR_VERSION_MAINNET 0x16)
;; #[allow(unused_const)]
(define-constant STACKS_ADDR_VERSION_TESTNET 0x1a)

;; Maximum number of cycles you can stake for
(define-constant MAX_NUM_CYCLES u24)

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
    ;; this stacker's first reward cycle is the _next_ reward cycle
    (begin
        ;;;;  Validate ownership of the given signer key
        ;; (try! (consume-signer-key-authorization pox-addr (- first-reward-cycle u1) "stack-stx" lock-period signer-sig signer-key amount-ustx max-amount auth-id))

        ;;  pox-addr must be valid
        (try! (check-pox-addr pox-addr))

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
        (asserts! (> amount-ustx u0) ERR_INVALID_AMOUNT)

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
        ;; TODO: verify signer sig

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
        ;; TODO: verify signer sig

        (try! (check-pox-addr pox-addr))

        (try! (contract-call? pool-owner validate-registration! tx-sender signer-key
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
        (auth-id uint)
    )
    (begin
        ;; TODO: verify signer sig

        ;;  pox-addr must be valid
        (try! (check-pox-addr pox-addr))

        (inner-stake-update amount-ustx-increase
            (err {
                pox-addr: pox-addr,
                signer-key: signer-key,
            })
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
