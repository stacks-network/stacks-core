(define-constant ERR_UNAUTHORIZED (err u1))
(define-constant ERR_CANNOT_SETUP_BOND_TOO_SOON (err u2))
(define-constant ERR_CANNOT_SETUP_BOND_TOO_LATE (err u3))
(define-constant ERR_BOND_ALREADY_SETUP (err u4))
(define-constant ERR_STAKER_ALREADY_ADDED (err u5))
(define-constant ERR_L1_LOCKUP_NOT_FOUND (err u6))
(define-constant ERR_BOND_NOT_FOUND (err u7))
(define-constant ERR_INSUFFICIENT_STX (err u8))
(define-constant ERR_ALREADY_REGISTERED (err u9))
(define-constant ERR_TOO_MUCH_SATS (err u10))
(define-constant ERR_NOT_ALLOWLISTED (err u11))
(define-constant ERR_SIGNER_KEY_GRANT_USED (err u12))
(define-constant ERR_INVALID_SIGNATURE_RECOVER (err u13))
(define-constant ERR_INVALID_SIGNATURE_PUBKEY (err u14))
(define-constant ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH (err u15))
(define-constant ERR_SIGNER_AUTH_USED (err u16))
(define-constant ERR_SIGNER_KEY_GRANT_NOT_FOUND (err u17))
(define-constant ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH (err u18))
(define-constant ERR_ALREADY_STAKED (err u19))
(define-constant ERR_INVALID_NUM_CYCLES (err u20))
(define-constant ERR_INVALID_POX_ADDRESS (err u21))
(define-constant ERR_UNAUTHORIZED_CALLER (err u22))
(define-constant ERR_POOL_NOT_FOUND (err u23))
(define-constant ERR_INVALID_START_BURN_HEIGHT (err u24))
(define-constant ERR_ALREADY_POOLED (err u25))
(define-constant ERR_UNAUTHORIZED_POOL_REGISTRATION (err u26))
(define-constant ERR_NOT_STAKING (err u27))

;; The length, in terms of staking cycles, of a given
;; bond period
(define-constant BOND_LENGTH_CYCLES u12)
;; The gap between the start of different bond periods
(define-constant BOND_GAP_CYCLES u2)
;; The maximum amount of time that a user can stake for
(define-constant MAX_NUM_CYCLES u12)

;; The minimum amount of uSTX that a staker must stake
;; to become part of the signer set
(define-constant SIGNER_SET_MIN_USTX u50000000000) ;; 50k STX

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

;; Values for stacks address versions
(define-constant STACKS_ADDR_VERSION_MAINNET 0x16)
(define-constant STACKS_ADDR_VERSION_TESTNET 0x1a)

(define-map protocol-bonds
    uint
    {
        ;; target yield rate (apy) in basis points
        target-rate: uint,
        ;; representation of STX:BTC price
        ;; this value is equal to "ustx per 100 sats", which
        ;; also translates to `(BTCUSD / STXUSD)`.
        ;; used to determine bond priority
        stx-value-ratio: uint,
        ;; minimum amount of STX that must be locked
        ;; relative to BTC for this term.
        ;; Represented in basis points.
        min-ustx-ratio: uint,
        ;; total amount of sats staked
        total-sats-shares: uint,
        ;; The allowed early unlock signers for this bond period
        early-unlock-signers: (buff 683),
    }
)

(define-map protocol-bond-allowances
    {
        bond-index: uint,
        staker: principal,
    }
    ;; max amount of sats they can contribute
    uint
)

(define-map protocol-bond-memberships
    principal
    {
        bond-index: uint,
        amount-sats: uint,
        pox-addr: (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }),
        ;; Used to calculate claimable rewards
        reward-per-share-paid: uint,
        amount-ustx: uint,
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

;; Mapping of staker (or pool) to signer key
(define-map staker-signer-keys
    principal
    (buff 33)
)

;; Users can stake to a pool, where the pool owner
;; (which is the key of this map) is able to manage
;; the signer key for the pool.
(define-map pools
    principal
    (buff 33) ;; signer key
)

;; Keep track of how much total STX has been staked for a pool
;; for a given cycle
(define-map pool-staked-per-cycle
    {
        pool: principal,
        cycle: uint,
    }
    uint
)

;; Keep track of a staker's high-level info
(define-map staker-info
    principal
    {
        amount-ustx: uint,
        first-reward-cycle: uint,
        num-cycles: uint,
    }
)

;; Per-cycle staker pool membership
(define-map staker-pool-cycle-memberships
    {
        staker: principal,
        cycle: uint,
    }
    {
        amount-ustx: uint,
        pool: principal,
    }
)

;; allowed contract-callers
(define-map allowance-contract-callers
    {
        sender: principal,
        contract-caller: principal,
    }
    ;; Optional expiration burn height
    (optional uint)
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
        pox-addr: (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }),
        auth-id: uint,
        max-amount: uint,
    }
    bool ;; Whether the field has been used or not
)

;; The role that is allowed to set bond parameters
(define-data-var bond-admin principal tx-sender)

;; Data vars that store a copy of the burnchain configuration.
;; Implemented as data-vars, so that different configurations can be
;; used in e.g. test harnesses.
;; #[allow(unused_data_var)]
(define-data-var pox-prepare-cycle-length uint (if is-in-mainnet
    u100
    u50
))
(define-data-var pox-reward-cycle-length uint (if is-in-mainnet
    u2100
    u1050
))
(define-data-var first-burnchain-block-height uint u0)
(define-data-var configured bool false)
;; The first reward cycle where pox-5 is active. This
;; is also equal to the first bond period.
;; #[allow(unused_data_var)]
(define-data-var first-pox-5-reward-cycle uint u0)

(define-trait pool-owner-trait (
    (validate-stake!
        ;; caller, amount-ustx, num-cycles
        (principal uint uint)
        (response bool uint)
    )
))

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

(define-public (setup-bond
        (bond-index uint)
        (target-rate uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
        (early-unlock-signers (buff 683))
        (allowlist (list 1000 {
            staker: principal,
            max-sats: uint,
        }))
    )
    (let ((bond-start-height (bond-period-to-burn-height bond-index)))
        ;; only bond admin can call this.
        (asserts! (is-eq contract-caller (var-get bond-admin)) ERR_UNAUTHORIZED)

        ;; only can be called within 2 cycles of bond start
        ;; (asserts! (> burn-block-height (- bond-start-height )))
        (asserts!
            (or
                ;; prevent underflow
                (< bond-start-height
                    (* BOND_GAP_CYCLES (var-get pox-reward-cycle-length))
                )
                (>
                    (- bond-start-height
                        (* BOND_GAP_CYCLES (var-get pox-reward-cycle-length))
                    )
                    burn-block-height
                )
            )
            ERR_CANNOT_SETUP_BOND_TOO_SOON
        )

        ;; only can be called before bond start
        (asserts! (< burn-block-height bond-start-height)
            ERR_CANNOT_SETUP_BOND_TOO_LATE
        )

        (asserts!
            (map-insert protocol-bonds bond-index {
                target-rate: target-rate,
                stx-value-ratio: stx-value-ratio,
                min-ustx-ratio: min-ustx-ratio,
                total-sats-shares: u0,
                early-unlock-signers: early-unlock-signers,
            })
            ERR_BOND_ALREADY_SETUP
        )

        (let ((accumulator (try! (fold add-staker-to-bond allowlist
                (ok {
                    sum-max-sats: u0,
                    bond-index: bond-index,
                })
            ))))
            (ok {
                bond-index: bond-index,
                target-rate: target-rate,
                stx-value-ratio: stx-value-ratio,
                min-ustx-ratio: min-ustx-ratio,
                early-unlock-signers: early-unlock-signers,
                max-allocation-sats: (get sum-max-sats accumulator),
            })
        )
    )
)

(define-private (add-staker-to-bond
        (staker-item {
            staker: principal,
            max-sats: uint,
        })
        (accumulator-res (response {
            sum-max-sats: uint,
            bond-index: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (bond-index (get bond-index accumulator))
        )
        (asserts!
            (map-insert protocol-bond-allowances {
                bond-index: bond-index,
                staker: (get staker staker-item),
            }
                (get max-sats staker-item)
            )
            ERR_STAKER_ALREADY_ADDED
        )
        (print (merge staker-item {
            topic: "add-to-allowlist",
            bond-index: bond-index,
        }))
        (ok {
            sum-max-sats: (+ (get sum-max-sats accumulator) (get max-sats staker-item)),
            bond-index: bond-index,
        })
    )
)

(define-public (register-for-bond
        (bond-index uint)
        ;; Where they want to receive BTC rewards. If this is `none`,
        ;; rewards are received as sBTC
        (pox-addr (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }))
        (signer-sig (optional (buff 65)))
        (signer-key (buff 33))
        (max-amount uint)
        (auth-id uint)
        (amount-ustx uint)
        ;; Their BTC lockup info. If the response is `ok`, then
        ;; this is a list of outputs corresponding to their timelocks.
        ;; If the response is `err`, this is the amount of sBTC (in sats)
        ;; that they want to lock.
        (btc-lockup (response {
            outputs: (list 10
                {
                    amount: uint,
                    txid: (buff 32),
                    output-index: uint,
                }
            ),
            unlock-bytes: (buff 683),
        }
            uint
        ))
    )
    (let (
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (lock-sbtc sbtc-amount)
            )))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (allowance (unwrap!
                (map-get? protocol-bond-allowances {
                    staker: tx-sender,
                    bond-index: bond-index,
                })
                ERR_NOT_ALLOWLISTED
            ))
            (first-reward-cycle (bond-period-to-reward-cycle bond-index))
        )
        ;; Verify that they're sending enough STX
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
        )

        (asserts! (<= sats-total allowance) ERR_TOO_MUCH_SATS)

        (try! (check-opt-pox-addr pox-addr))

        ;; Validate their signer key usage
        (try! (validate-signer-key-usage pox-addr (current-pox-reward-cycle) "stake"
            BOND_LENGTH_CYCLES signer-sig signer-key amount-ustx max-amount
            auth-id tx-sender
        ))

        ;;;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        (asserts! (is-none (get-bond-membership tx-sender))
            ERR_ALREADY_REGISTERED
        )

        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-sats: sats-total,
            pox-addr: pox-addr,
            reward-per-share-paid: u0,
            amount-ustx: amount-ustx,
        })

        (map-set staker-signer-keys tx-sender signer-key)

        (try! (add-staker-to-reward-cycles tx-sender first-reward-cycle
            BOND_LENGTH_CYCLES
        ))

        (ok true)
    )
)

;; Register a pool
(define-public (register-pool
        (pool-owner <pool-owner-trait>)
        (signer-key (buff 33))
    )
    (let ((pool (contract-of pool-owner)))
        ;; Because pools can have members register at any time,
        ;; they must use signer key grants instead of per-tx
        ;; authorizations.
        (try! (verify-signer-key-grant tx-sender signer-key none))

        ;; Only the pool contract itself can register itself
        (asserts! (is-eq tx-sender pool) ERR_UNAUTHORIZED_POOL_REGISTRATION)

        (map-set pools pool signer-key)
        (map-set staker-signer-keys pool signer-key)
        (ok {
            pool: pool,
            signer-key: signer-key,
        })
    )
)

;; Stake your STX
(define-public (stake
        (pool-or-signer-key (response <pool-owner-trait> (buff 33)))
        (amount-ustx uint)
        (num-cycles uint)
        (start-burn-ht uint)
    )
    (let (
            (pool (match pool-or-signer-key
                owner (contract-of owner)
                signer-key tx-sender
            ))
            (current-cycle (current-pox-reward-cycle))
            (first-reward-cycle (+ u1 current-cycle))
            (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht)))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle num-cycles))
        )
        (match pool-or-signer-key
            ;; Validate that the staker can join this pool
            owner
            (begin
                (try! (contract-call? owner validate-stake! tx-sender amount-ustx
                    num-cycles
                ))
                ;; The pool must have been registered already
                (asserts! (is-some (get-pool-info pool)) ERR_POOL_NOT_FOUND)
            )
            ;; Validate signer key usage
            signer-key
            (begin
                (try! (verify-signer-key-grant tx-sender signer-key none))
                (map-set staker-signer-keys tx-sender signer-key)
            )
        )

        ;; the start-burn-ht must result in the next reward cycle, do not allow stackers
        ;;  to "post-date" their transaction
        (asserts! (is-eq first-reward-cycle specified-reward-cycle)
            ERR_INVALID_START_BURN_HEIGHT
        )

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;;;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; Cannot be already pooled
        (asserts! (is-none (get-staker-info tx-sender)) ERR_ALREADY_POOLED)

        ;;;;  tx-sender principal must not be in a bond membership
        (asserts! (is-none (get-bond-membership tx-sender)) ERR_ALREADY_STAKED)

        ;;;;  the Stacker must have sufficient unlocked funds
        (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
            ERR_INSUFFICIENT_STX
        )

        (try! (add-staker-to-pool-cycles tx-sender pool first-reward-cycle num-cycles
            amount-ustx
        ))

        (map-set staker-info tx-sender {
            amount-ustx: amount-ustx,
            first-reward-cycle: first-reward-cycle,
            num-cycles: num-cycles,
        })

        (ok {
            pool: pool,
            staker: tx-sender,
            amount-ustx: amount-ustx,
            num-cycle: num-cycles,
            first-reward-cycle: first-reward-cycle,
            unlock-burn-height: (reward-cycle-to-unlock-height unlock-cycle),
            unlock-cycle: unlock-cycle,
        })
    )
)

;; A user can:
;; - Change pools
;; - Extend their lock
;; - Increase STX locked
(define-public (stake-update
        (pool-or-signer-key (response <pool-owner-trait> (buff 33)))
        (cycles-to-extend uint)
        (amount-increase uint)
    )
    (let (
            (pool (match pool-or-signer-key
                owner (contract-of owner)
                signer-key tx-sender
            ))
            (current-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKING))
            ;; This is the first cycle where their STX would be unlocked
            (prev-unlock-cycle (+ (get first-reward-cycle current-info)
                (get num-cycles current-info)
            ))
            (unlock-cycle (+ prev-unlock-cycle cycles-to-extend))
            (new-lock-amount (+ (get amount-ustx current-info) amount-increase))
            (current-cycle (current-pox-reward-cycle))
            (num-cycles (- unlock-cycle current-cycle u1))
        )
        ;; Validate that the staker can join this pool
        (match pool-or-signer-key
            owner (begin
                (try! (contract-call? owner validate-stake! tx-sender new-lock-amount
                    num-cycles
                ))
                ;; The pool must have been registered already
                (asserts! (is-some (get-pool-info pool)) ERR_POOL_NOT_FOUND)
            )
            signer-key (begin
                (try! (verify-signer-key-grant tx-sender signer-key none))
                (map-set staker-signer-keys tx-sender signer-key)
            )
        )

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;;;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; Must have enough unlocked STX
        (asserts! (>= (get unlocked (stx-account tx-sender)) amount-increase)
            ERR_INSUFFICIENT_STX
        )

        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender (+ u1 current-cycle)
            (- prev-unlock-cycle current-cycle u1)
        ))

        (try! (add-staker-to-pool-cycles tx-sender pool (+ u1 current-cycle) num-cycles
            new-lock-amount
        ))

        (map-set staker-info tx-sender {
            amount-ustx: new-lock-amount,
            first-reward-cycle: (get first-reward-cycle current-info),
            num-cycles: (+ (get num-cycles current-info) cycles-to-extend),
        })

        (ok {
            unlock-burn-height: (reward-cycle-to-unlock-height unlock-cycle),
            staker: tx-sender,
            pool: pool,
            prev-unlock-height: prev-unlock-cycle,
            unlock-cycle: unlock-cycle,
            num-cycles: num-cycles,
            amount-ustx: new-lock-amount,
        })
    )
)

;; Unstake - set your STX to unlock at the end of the current cycle
(define-public (unstake)
    (let (
            (current-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKING))
            (first-reward-cycle (get first-reward-cycle current-info))
            ;; This is the first cycle where their STX would be unlocked
            (prev-unlock-cycle (+ first-reward-cycle (get num-cycles current-info)))
            (current-cycle (current-pox-reward-cycle))
            (unlock-cycle (+ current-cycle u1))
        )
        ;;;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; TODO: do not allow during a prepare phase

        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender (+ u1 current-cycle)
            (- prev-unlock-cycle current-cycle u1)
        ))

        (map-set staker-info tx-sender {
            amount-ustx: (get amount-ustx current-info),
            first-reward-cycle: first-reward-cycle,
            num-cycles: (- unlock-cycle first-reward-cycle),
        })

        (ok {
            staker: tx-sender,
            amount-ustx: (get amount-ustx current-info),
            first-reward-cycle: first-reward-cycle,
            unlock-cycle: unlock-cycle,
            unlock-burn-height: (reward-cycle-to-unlock-height unlock-cycle),
        })
    )
)

;;;;  Remove a staker from a pool for X cycles
(define-private (remove-staker-from-cycles
        (staker principal)
        (first-reward-cycle uint)
        (num-cycles uint)
    )
    (ok (try! (fold remove-staker-from-pool-for-cycle
        ;; panic is ok here because we've already checked `num-cycles`
        (unwrap-panic (slice? (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11) u0 num-cycles))
        (ok {
            staker: staker,
            first-reward-cycle: first-reward-cycle,
        })
    )))
)

;; For a given (staker, pool, cycle), remove a staker from
;; that pool. If the pool has gone below the minimum amount to
;; be in the signer set, remove them from the signer set.
(define-private (remove-staker-from-pool-for-cycle
        (cycle-index uint)
        (accumulator-res (response {
            staker: principal,
            first-reward-cycle: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (staker (get staker accumulator))
            (cycle (+ cycle-index (get first-reward-cycle accumulator)))
            (membership (unwrap!
                (map-get? staker-pool-cycle-memberships {
                    staker: staker,
                    cycle: cycle,
                })
                ERR_NOT_STAKING
            ))
            (pool (get pool membership))
            (cur-staked-for-pool (get-current-amount-staked-for-pool pool cycle))
            (new-staked (- cur-staked-for-pool (get amount-ustx membership)))
            (is-in-signer-set (is-some (get-staker-set-item-for-cycle pool cycle)))
        )
        (if (and is-in-signer-set (< new-staked SIGNER_SET_MIN_USTX))
            ;; They've crossed back below the threshold - remove from the signer set
            (try! (remove-staker-from-set-for-cycle pool cycle))
            true
        )
        (map-delete staker-pool-cycle-memberships {
            staker: staker,
            cycle: cycle,
        })
        (map-set pool-staked-per-cycle {
            cycle: cycle,
            pool: pool,
        }
            new-staked
        )
        (ok accumulator)
    )
)

(define-private (add-staker-to-pool-cycles
        (staker principal)
        (pool principal)
        (first-reward-cycle uint)
        (num-cycles uint)
        (amount-ustx uint)
    )
    (ok (try! (fold add-staker-to-pool-for-cycle
        ;; panic is ok here because we've already checked `num-cycles`
        (unwrap-panic (slice? (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11) u0 num-cycles))
        (ok {
            staker: staker,
            pool: pool,
            amount-ustx: amount-ustx,
            first-reward-cycle: first-reward-cycle,
        })
    )))
)

;; For a given (staker, pool, cycle), update pool state for that
;; cycle and lazily add the pool to the signer set if needed
(define-private (add-staker-to-pool-for-cycle
        (cycle-index uint)
        (accumulator-res (response {
            pool: principal,
            staker: principal,
            amount-ustx: uint,
            first-reward-cycle: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (cycle (+ cycle-index (get first-reward-cycle accumulator)))
            (pool (get pool accumulator))
            (cur-staked-for-pool (get-current-amount-staked-for-pool pool cycle))
            (new-staked (+ cur-staked-for-pool (get amount-ustx accumulator)))
        )
        (if (and (< cur-staked-for-pool SIGNER_SET_MIN_USTX) (>= new-staked SIGNER_SET_MIN_USTX))
            ;; They've crossed the threshold - add the pool to the signer set linked list
            (try! (add-staker-to-set-for-cycle pool cycle))
            true
        )
        (map-set staker-pool-cycle-memberships {
            staker: (get staker accumulator),
            cycle: cycle,
        } {
            pool: pool,
            amount-ustx: (get amount-ustx accumulator),
        })
        (map-set pool-staked-per-cycle {
            cycle: cycle,
            pool: pool,
        }
            new-staked
        )
        (ok accumulator)
    )
)

(define-private (lock-sbtc (amount uint))
    (begin
        (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
            transfer amount tx-sender current-contract none
        ))
        (ok amount)
    )
)

;; Verify l1 lockup information for a staker. This asserts that each lockup
;; corresponds to the right timelock script for this staker, and that the lockup
;; occurred on-chain. If everything is valid, this returns the sum of all lockups in sats.
(define-private (verify-l1-lockups
        ;; #[allow(unused_binding)]
        (staker principal)
        ;; #[allow(unused_binding)]
        (bond-index uint)
        (lockups {
            outputs: (list 10
                {
                    amount: uint,
                    txid: (buff 32),
                    output-index: uint,
                }
            ),
            unlock-bytes: (buff 683),
        })
    )
    (let ((accumulation (try! (fold validate-l1-lockup (get outputs lockups)
            (ok {
                sum: u0,
                ;; TODO: construct the correct lockup script
                expected-script-hash: 0xdeadbeef,
            })
        ))))
        (ok (get sum accumulation))
    )
)

;; Fold function for validating l1 lockup info
(define-private (validate-l1-lockup
        (lockup {
            amount: uint,
            txid: (buff 32),
            output-index: uint,
        })
        (accumulator-res (response {
            expected-script-hash: (buff 32),
            sum: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (actual-amount (try! (validate-p2wsh-exists? (get expected-script-hash accumulator)
                (get amount lockup) (get txid lockup)
                (get output-index lockup)
            )))
        )
        (asserts! (is-eq actual-amount (get amount lockup))
            ERR_L1_LOCKUP_NOT_FOUND
        )
        (ok {
            expected-script-hash: (get expected-script-hash accumulator),
            sum: (+ (get sum accumulator) (get amount lockup)),
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
            ERR_UNAUTHORIZED
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
        (pox-addr (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }))
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
        (pox-addr (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }))
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
        (pox-addr (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }))
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
        (pox-addr (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }))
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
        (pox-addr (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }))
    )
    (ok (asserts!
        (match (unwrap!
            (map-get? signer-key-grants {
                signer-key: signer-key,
                staker: staker,
            })
            ERR_SIGNER_KEY_GRANT_NOT_FOUND
        )
            grant-pox-addr (is-eq grant-pox-addr
                (unwrap! pox-addr ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH)
            )
            true
        )
        ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH
    ))
)

;;; Helper functions

;; This is a stand-in for a future built-in clarity function.
(define-private (validate-p2wsh-exists?
        ;; #[allow(unused_binding)]
        (script-hash (buff 32))
        (amount uint)
        ;; #[allow(unused_binding)]
        (txid (buff 32))
        ;; #[allow(unused_binding)]
        (output-index uint)
    )
    (if (is-eq amount u0)
        ERR_L1_LOCKUP_NOT_FOUND
        (ok amount)
    )
)

;; What's the burn height at the start of a given bond index?
(define-read-only (bond-period-to-burn-height (bond-index uint))
    (reward-cycle-to-burn-height (bond-period-to-reward-cycle bond-index))
)

;; What reward cycle does a bond index start at?
(define-read-only (bond-period-to-reward-cycle (bond-index uint))
    (+ (var-get first-pox-5-reward-cycle) (* bond-index BOND_GAP_CYCLES))
)

;; What's the reward cycle number of the burnchain block height?
;; Will runtime-abort if height is less than the first burnchain block (this is intentional)
(define-read-only (burn-height-to-reward-cycle (height uint))
    (/ (- height (var-get first-burnchain-block-height))
        (var-get pox-reward-cycle-length)
    )
)

;; What's the burn height at the start of a given reward cycle?
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

;; Used for PoX parameters discovery
(define-read-only (get-pox-info)
    (ok {
        min-amount-ustx: SIGNER_SET_MIN_USTX,
        reward-cycle-id: (current-pox-reward-cycle),
        prepare-cycle-length: (var-get pox-prepare-cycle-length),
        first-burnchain-block-height: (var-get first-burnchain-block-height),
        reward-cycle-length: (var-get pox-reward-cycle-length),
        total-liquid-supply-ustx: stx-liquid-supply,
    })
)

(define-read-only (get-bond-allowance
        (bond-index uint)
        (staker principal)
    )
    (map-get? protocol-bond-allowances {
        bond-index: bond-index,
        staker: staker,
    })
)

;; Get _current_ bond member info
(define-read-only (get-bond-membership (staker principal))
    (match (map-get? protocol-bond-memberships staker)
        membership (if (<=
                (+ BOND_LENGTH_CYCLES
                    (bond-period-to-reward-cycle (get bond-index membership))
                )
                (current-pox-reward-cycle)
            )
            none
            (some membership)
        )
        none
    )
)

;; For a given `stx-value-ratio`, which represents "ustx per 100 sats",
;; and a given `min-ustx-ratio`, which represents a minimum amount
;; of STX that must be locked relative to BTC (in basis points),
;; and a given `sats-amount`, calculate the minimum amount
;; of STX needed to hit `min-ustx-ratio`.
;;
;; This is equal to the value-weighted amount of `sats-amount` multiplied
;; by the percentage of `min-ustx-ratio` in STX terms.
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)

;; Get the _current_ info for a staker. If their
;; stake has expired, this will return `none`.
(define-read-only (get-staker-info (staker principal))
    (match (map-get? staker-info staker)
        pool-info
        (if (<= (+ (get first-reward-cycle pool-info) (get num-cycles pool-info))
                (current-pox-reward-cycle)
            )
            ;; present, but lock has expired
            none
            ;; present, and lock has not expired
            (some pool-info)
        )
        ;; no state at all
        none
    )
)

(define-read-only (get-pool-info (pool principal))
    (map-get? pools pool)
)

(define-read-only (get-current-amount-staked-for-pool
        (pool principal)
        (cycle uint)
    )
    (default-to u0
        (map-get? pool-staked-per-cycle {
            cycle: cycle,
            pool: pool,
        })
    )
)

;; Get per-cycle staker pool membership info
(define-read-only (get-pool-cycle-membership
        (staker principal)
        (cycle uint)
    )
    (map-get? staker-pool-cycle-memberships {
        staker: staker,
        cycle: cycle,
    })
)

(define-read-only (get-signer-key (staker principal))
    (map-get? staker-signer-keys staker)
)

(define-private (check-opt-pox-addr (pox-addr-opt (optional {
    version: (buff 1),
    hashbytes: (buff 32),
})))
    (match pox-addr-opt
        pox-addr (check-pox-addr pox-addr)
        (ok true)
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

(define-read-only (check-pox-lock-period (lock-period uint))
    (and
        (>= lock-period u1)
        (<= lock-period MAX_NUM_CYCLES)
    )
)

;;; Contract caller allowances

(define-read-only (check-caller-allowed)
    (ok (asserts!
        (or
            (is-eq tx-sender contract-caller)
            (match (unwrap!
                (map-get? allowance-contract-callers {
                    sender: tx-sender,
                    contract-caller: contract-caller,
                })
                ERR_UNAUTHORIZED_CALLER
            )
                expiration (>= burn-block-height expiration)
                true
            )
        )
        ERR_UNAUTHORIZED_CALLER
    ))
)

;; Revoke contract-caller authorization to call stacking methods
(define-public (disallow-contract-caller (caller principal))
    (begin
        (asserts! (is-eq tx-sender contract-caller) ERR_UNAUTHORIZED_CALLER)
        (ok (map-delete allowance-contract-callers {
            sender: tx-sender,
            contract-caller: caller,
        }))
    )
)

;; Give a contract-caller authorization to call stacking methods
;;  normally, stacking methods may only be invoked by _direct_ transactions
;;   (i.e., the tx-sender issues a direct contract-call to the stacking methods)
;;  by issuing an allowance, the tx-sender may call through the allowed contract
(define-public (allow-contract-caller
        (caller principal)
        (until-burn-ht (optional uint))
    )
    (begin
        (asserts! (is-eq tx-sender contract-caller) ERR_UNAUTHORIZED_CALLER)
        (ok (map-set allowance-contract-callers {
            sender: tx-sender,
            contract-caller: caller,
        }
            until-burn-ht
        ))
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

(define-public (remove-staker-from-set-for-cycle
        (stacker principal)
        (cycle uint)
    )
    (let (
            (node (unwrap!
                (map-get? staker-set-ll-for-cycle {
                    cycle: cycle,
                    staker: stacker,
                })
                ERR_NOT_STAKING
            ))
            (prev-item (get prev node))
            (next-item (get next node))
        )
        (match prev-item
            prev-stacker
            (map-set staker-set-ll-for-cycle {
                cycle: cycle,
                staker: prev-stacker,
            } {
                prev: (get prev
                    (unwrap-panic (map-get? staker-set-ll-for-cycle {
                        staker: prev-stacker,
                        cycle: cycle,
                    }))
                ),
                next: next-item,
            })
            ;; this is the first item
            (match next-item
                next
                (map-set staker-set-ll-first-for-cycle cycle next)
                ;; no previous or next - this is the only item
                (begin
                    (map-delete staker-set-ll-last-for-cycle cycle)
                    (map-delete staker-set-ll-first-for-cycle cycle)
                )
            )
        )

        (match next-item
            next-stacker (map-set staker-set-ll-for-cycle {
                cycle: cycle,
                staker: next-stacker,
            } {
                prev: prev-item,
                next: (get next
                    (unwrap-panic (map-get? staker-set-ll-for-cycle {
                        staker: next-stacker,
                        cycle: cycle,
                    }))
                ),
            })
            (match prev-item
                prev-stacker
                (map-set staker-set-ll-last-for-cycle cycle prev-stacker)
                ;; This is the only item - we've already handled this, though
                true
            )
        )
        (map-delete staker-set-ll-for-cycle {
            cycle: cycle,
            staker: stacker,
        })
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
