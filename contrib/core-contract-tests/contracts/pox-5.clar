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
(define-constant ERR_SIGNER_NOT_FOUND (err u23))
(define-constant ERR_INVALID_START_BURN_HEIGHT (err u24))
(define-constant ERR_UNAUTHORIZED_SIGNER_REGISTRATION (err u26))
(define-constant ERR_NOT_STAKING (err u27))
(define-constant ERR_UNSTAKE_IN_PREPARE_PHASE (err u28))

;; The length, in terms of staking cycles, of a given
;; bond period
(define-constant BOND_LENGTH_CYCLES u12)
;; The gap between the start of different bond periods
(define-constant BOND_GAP_CYCLES u2)
;; The maximum amount of time that a user can stake for
(define-constant MAX_NUM_CYCLES u96)

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
        ;; Used to calculate claimable rewards
        reward-per-share-paid: uint,
        amount-ustx: uint,
    }
)

(define-map signer-key-grants
    {
        signer-key: (buff 33),
        signer-manager: principal,
    }
    bool
)

(define-map used-signer-key-grants
    {
        signer-key: (buff 33),
        signer-manager: principal,
        auth-id: uint,
    }
    bool
)

;; Mapping of staker (or signer) to signer key
(define-map signer-keys
    principal
    (buff 33)
)

;; Users can stake to a signer, where the signer owner
;; (which is the key of this map) is able to manage
;; the signer key for the signer.
(define-map signers
    principal
    (buff 33) ;; signer key
)

;; Keep track of how much total STX has been staked for a signer
;; for a given cycle
(define-map signer-staked-per-cycle
    {
        signer: principal,
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

;; Per-cycle staker signer membership
(define-map staker-signer-cycle-memberships
    {
        staker: principal,
        cycle: uint,
    }
    {
        amount-ustx: uint,
        signer: principal,
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

(define-trait signer-manager-trait (
    (validate-stake!
        ;; caller, amount-ustx, num-cycles, signer-calldata
        (principal uint uint (optional (buff 500)))
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
        (signer-manager <signer-manager-trait>)
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
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
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

        ;; Validate that the staker can join this signer
        (try! (contract-call? signer-manager validate-stake! tx-sender amount-ustx u12
            signer-calldata
        ))
        ;; The signer must have been registered already
        (asserts! (is-some (get-signer-info signer)) ERR_SIGNER_NOT_FOUND)

        ;;;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        (asserts! (is-none (get-bond-membership tx-sender))
            ERR_ALREADY_REGISTERED
        )

        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-sats: sats-total,
            reward-per-share-paid: u0,
            amount-ustx: amount-ustx,
        })
        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            BOND_LENGTH_CYCLES amount-ustx
        ))

        (ok true)
    )
)

;; Register a signer
(define-public (register-signer
        (signer-manager <signer-manager-trait>)
        (signer-key (buff 33))
    )
    (let ((signer (contract-of signer-manager)))
        ;; Because signers can have members register at any time,
        ;; they must use signer key grants instead of per-tx
        ;; authorizations.
        (try! (verify-signer-key-grant signer signer-key))

        ;; Only the signer contract itself can register itself
        (asserts! (is-eq tx-sender signer) ERR_UNAUTHORIZED_SIGNER_REGISTRATION)

        (map-set signers signer signer-key)
        (map-set signer-keys signer signer-key)
        (ok {
            signer: signer,
            signer-key: signer-key,
        })
    )
)

;; Stake your STX
(define-public (stake
        (signer-manager <signer-manager-trait>)
        (amount-ustx uint)
        (num-cycles uint)
        (start-burn-ht uint)
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            (current-cycle (current-pox-reward-cycle))
            (first-reward-cycle (+ u1 current-cycle))
            (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht)))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle num-cycles))
        )
        ;; Validate that the staker can join this signer
        (try! (contract-call? signer-manager validate-stake! tx-sender amount-ustx
            num-cycles signer-calldata
        ))
        ;; The signer must have been registered already
        (asserts! (is-some (get-signer-info signer)) ERR_SIGNER_NOT_FOUND)

        ;; the start-burn-ht must result in the next reward cycle, do not allow stackers
        ;;  to "post-date" their transaction
        (asserts! (is-eq first-reward-cycle specified-reward-cycle)
            ERR_INVALID_START_BURN_HEIGHT
        )

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;;;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; Cannot be already staked
        (asserts! (is-none (get-staker-info tx-sender)) ERR_ALREADY_STAKED)

        ;;;;  tx-sender principal must not be in a bond membership
        (asserts! (is-none (get-bond-membership tx-sender)) ERR_ALREADY_STAKED)

        ;;;;  the Stacker must have sufficient unlocked funds
        (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
            ERR_INSUFFICIENT_STX
        )

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            num-cycles amount-ustx
        ))

        (map-set staker-info tx-sender {
            amount-ustx: amount-ustx,
            first-reward-cycle: first-reward-cycle,
            num-cycles: num-cycles,
        })

        (ok {
            signer: signer,
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
;; - Change signers
;; - Extend their lock
;; - Increase STX locked
(define-public (stake-update
        (signer-manager <signer-manager-trait>)
        (cycles-to-extend uint)
        (amount-increase uint)
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
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
        ;; Validate that the staker can join this signer
        (try! (contract-call? signer-manager validate-stake! tx-sender new-lock-amount
            num-cycles signer-calldata
        ))
        ;; The signer must have been registered already
        (asserts! (is-some (get-signer-info signer)) ERR_SIGNER_NOT_FOUND)

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

        (try! (add-staker-to-signer-cycles tx-sender signer (+ u1 current-cycle)
            num-cycles new-lock-amount
        ))

        (map-set staker-info tx-sender {
            amount-ustx: new-lock-amount,
            first-reward-cycle: (get first-reward-cycle current-info),
            num-cycles: (+ (get num-cycles current-info) cycles-to-extend),
        })

        (ok {
            unlock-burn-height: (reward-cycle-to-unlock-height unlock-cycle),
            staker: tx-sender,
            signer: signer,
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

        ;; do not allow during a prepare phase
        (asserts! (not (is-in-prepare-phase current-cycle))
            ERR_UNSTAKE_IN_PREPARE_PHASE
        )

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

;;;;  Remove a staker from a signer for X cycles
(define-private (remove-staker-from-cycles
        (staker principal)
        (first-reward-cycle uint)
        (num-cycles uint)
    )
    (ok (try! (fold remove-staker-from-signer-for-cycle
        ;; panic is ok here because we've already checked `num-cycles`
        (unwrap-panic (slice?
            (list
                u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16
                u17 u18 u19 u20 u21 u22 u23 u24 u25 u26 u27 u28 u29 u30 u31
                u32 u33 u34 u35 u36 u37 u38 u39 u40 u41 u42 u43 u44 u45 u46
                u47 u48 u49 u50 u51 u52 u53 u54 u55 u56 u57 u58 u59 u60 u61
                u62 u63 u64 u65 u66 u67 u68 u69 u70 u71 u72 u73 u74 u75 u76
                u77 u78 u79 u80 u81 u82 u83 u84 u85 u86 u87 u88 u89 u90 u91
                u92 u93 u94 u95
            )
            u0 num-cycles
        ))
        (ok {
            staker: staker,
            first-reward-cycle: first-reward-cycle,
        })
    )))
)

;; For a given (staker, signer, cycle), remove a staker from
;; that signer. If the signer has gone below the minimum amount to
;; be in the signer set, remove them from the signer set.
(define-private (remove-staker-from-signer-for-cycle
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
                (map-get? staker-signer-cycle-memberships {
                    staker: staker,
                    cycle: cycle,
                })
                ERR_NOT_STAKING
            ))
            (signer (get signer membership))
            (cur-staked-for-signer (get-current-amount-staked-for-signer signer cycle))
            (new-staked (- cur-staked-for-signer (get amount-ustx membership)))
            (is-in-signer-set (is-some (get-staker-set-item-for-cycle signer cycle)))
        )
        (if (and is-in-signer-set (< new-staked SIGNER_SET_MIN_USTX))
            ;; They've crossed back below the threshold - remove from the signer set
            (try! (remove-staker-from-set-for-cycle signer cycle))
            true
        )
        (map-delete staker-signer-cycle-memberships {
            staker: staker,
            cycle: cycle,
        })
        (map-set signer-staked-per-cycle {
            cycle: cycle,
            signer: signer,
        }
            new-staked
        )
        (ok accumulator)
    )
)

(define-private (add-staker-to-signer-cycles
        (staker principal)
        (signer principal)
        (first-reward-cycle uint)
        (num-cycles uint)
        (amount-ustx uint)
    )
    (ok (try! (fold add-staker-to-signer-for-cycle
        ;; panic is ok here because we've already checked `num-cycles`
        (unwrap-panic (slice?
            (list
                u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11 u12 u13 u14 u15 u16
                u17 u18 u19 u20 u21 u22 u23 u24 u25 u26 u27 u28 u29 u30 u31
                u32 u33 u34 u35 u36 u37 u38 u39 u40 u41 u42 u43 u44 u45 u46
                u47 u48 u49 u50 u51 u52 u53 u54 u55 u56 u57 u58 u59 u60 u61
                u62 u63 u64 u65 u66 u67 u68 u69 u70 u71 u72 u73 u74 u75 u76
                u77 u78 u79 u80 u81 u82 u83 u84 u85 u86 u87 u88 u89 u90 u91
                u92 u93 u94 u95
            )
            u0 num-cycles
        ))
        (ok {
            staker: staker,
            signer: signer,
            amount-ustx: amount-ustx,
            first-reward-cycle: first-reward-cycle,
        })
    )))
)

;; For a given (staker, signer, cycle), update signer state for that
;; cycle and lazily add the signer to the signer set if needed
(define-private (add-staker-to-signer-for-cycle
        (cycle-index uint)
        (accumulator-res (response {
            signer: principal,
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
            (signer (get signer accumulator))
            (cur-staked-for-signer (get-current-amount-staked-for-signer signer cycle))
            (new-staked (+ cur-staked-for-signer (get amount-ustx accumulator)))
        )
        (if (and (< cur-staked-for-signer SIGNER_SET_MIN_USTX) (>= new-staked SIGNER_SET_MIN_USTX))
            ;; They've crossed the threshold - add the signer to the signer set linked list
            (try! (add-staker-to-set-for-cycle signer cycle))
            true
        )
        (map-set staker-signer-cycle-memberships {
            staker: (get staker accumulator),
            cycle: cycle,
        } {
            signer: signer,
            amount-ustx: (get amount-ustx accumulator),
        })
        (map-set signer-staked-per-cycle {
            cycle: cycle,
            signer: signer,
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
        (signer-manager principal)
        (auth-id uint)
        (signer-sig (buff 65))
    )
    (begin
        (asserts!
            (is-none (map-get? used-signer-key-grants {
                signer-key: signer-key,
                signer-manager: signer-manager,
                auth-id: auth-id,
            }))
            ERR_SIGNER_KEY_GRANT_USED
        )

        (asserts!
            (is-eq
                (unwrap!
                    (secp256k1-recover?
                        (get-signer-grant-message-hash signer-manager auth-id)
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
                signer-manager: signer-manager,
                auth-id: auth-id,
            }
                true
            )
            ERR_SIGNER_KEY_GRANT_USED
        )

        (map-set signer-key-grants {
            signer-key: signer-key,
            signer-manager: signer-manager,
        }
            true
        )

        (ok true)
    )
)

;; Revoke a signer key grant for a staker. Only the Stacks principal
;; associated with `signer-key` can call this function.
;;
;; Returns a boolean indicating whether the signer key grant existed.
(define-public (revoke-signer-grant
        (signer-manager principal)
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
            signer-manager: signer-manager,
        }))
    )
)

;; Construct the message hash for validating a signer key grant. Unlike [get-signer-key-message-hash],
;; this message hash does not include `max-amount`, `period`, or `reward-cycle`. The topic is always `"grant-authorization"`.
;; The `pox-addr` field is optional. When `none`, it means the signer key can be used for any PoX address.
(define-read-only (get-signer-grant-message-hash
        (signer-manager principal)
        (auth-id uint)
    )
    (sha256 (concat SIP018_MSG_PREFIX
        (concat (sha256 (unwrap-panic (to-consensus-buff? POX_5_SIGNER_DOMAIN)))
            (sha256 (unwrap-panic (to-consensus-buff? {
                topic: "grant-authorization",
                signer-manager: signer-manager,
                auth-id: auth-id,
            })))
        )))
)

(define-read-only (verify-signer-key-grant
        (signer-manager principal)
        (signer-key (buff 33))
    )
    (ok (asserts!
        (is-some (map-get? signer-key-grants {
            signer-key: signer-key,
            signer-manager: signer-manager,
        }))
        ERR_SIGNER_KEY_GRANT_NOT_FOUND
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

;; Are we currently in a prepare phase at the end of `current-cycle`?
(define-read-only (is-in-prepare-phase (current-cycle uint))
    (>= burn-block-height
        (- (reward-cycle-to-unlock-height (+ current-cycle u1))
            (var-get pox-prepare-cycle-length)
        ))
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
        signer-info
        (if (<=
                (+ (get first-reward-cycle signer-info)
                    (get num-cycles signer-info)
                )
                (current-pox-reward-cycle)
            )
            ;; present, but lock has expired
            none
            ;; present, and lock has not expired
            (some signer-info)
        )
        ;; no state at all
        none
    )
)

(define-read-only (get-signer-info (signer principal))
    (map-get? signers signer)
)

(define-read-only (get-current-amount-staked-for-signer
        (signer principal)
        (cycle uint)
    )
    (default-to u0
        (map-get? signer-staked-per-cycle {
            cycle: cycle,
            signer: signer,
        })
    )
)

;; Get per-cycle staker signer membership info
(define-read-only (get-signer-cycle-membership
        (staker principal)
        (cycle uint)
    )
    (map-get? staker-signer-cycle-memberships {
        staker: staker,
        cycle: cycle,
    })
)

(define-read-only (get-signer-key (staker principal))
    (map-get? signer-keys staker)
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
