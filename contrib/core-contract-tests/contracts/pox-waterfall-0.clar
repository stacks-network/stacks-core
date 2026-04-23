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

(define-constant BOND_LENGTH_CYCLES u12)
(define-constant BOND_GAP_CYCLES u2)

(define-map protocol-bonds
    uint
    {
        ;; target yield rate (apy) in basis points
        target-rate: uint,
        ;; representation of STX:BTC price
        ;; this value is equal to "ustx per 1000 sats".
        ;; used to determine bond seniority
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

(define-map protocol-bond-members
    {
        bond-index: uint,
        staker: principal,
    }
    {
        amount-sats: uint,
        pox-addr: (optional {
            version: (buff 1),
            hashbytes: (buff 32),
        }),
        ;; Used to calculate claimable rewards
        reward-per-share-paid: uint,
    }
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
;; The first reward cycle where pox-wf is active. This
;; is also equal to the first bond period.
;; #[allow(unused_data_var)]
(define-data-var first-pox-wf-reward-cycle uint u0)

;; This function can only be called once, when it boots up
(define-public (set-burnchain-parameters
        (first-burn-height uint)
        (prepare-cycle-length uint)
        (reward-cycle-length uint)
        (begin-wf-reward-cycle uint)
    )
    (begin
        (unwrap-panic (if (var-get configured)
            (err false)
            (ok true)
        ))
        (var-set first-burnchain-block-height first-burn-height)
        (var-set pox-prepare-cycle-length prepare-cycle-length)
        (var-set pox-reward-cycle-length reward-cycle-length)
        (var-set first-pox-wf-reward-cycle begin-wf-reward-cycle)
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

        (try! (fold add-staker-to-bond allowlist
            (ok {
                sum-max-sats: u0,
                bond-index: bond-index,
            })
        ))

        (ok true)
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
    (let ((accumulator (try! accumulator-res)))
        (asserts!
            (map-insert protocol-bond-allowances {
                bond-index: (get bond-index accumulator),
                staker: (get staker staker-item),
            }
                (get max-sats staker-item)
            )
            ERR_STAKER_ALREADY_ADDED
        )
        (ok {
            sum-max-sats: (+ (get sum-max-sats accumulator) (get max-sats staker-item)),
            bond-index: (get bond-index accumulator),
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
        ;; #[allow(unused_binding)]
        (signer-sig (optional (buff 65)))
        ;; #[allow(unused_binding)]
        (signer-key (buff 33))
        ;; #[allow(unused_binding)]
        (max-amount uint)
        ;; #[allow(unused_binding)]
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
            (ustx-value-of-sats (/ (* (get stx-value-ratio bond) sats-total) u1000))
            (min-amount-ustx (/ (* ustx-value-of-sats (get min-ustx-ratio bond)) u10000))
            (allowance (unwrap!
                (map-get? protocol-bond-allowances {
                    staker: tx-sender,
                    bond-index: bond-index,
                })
                ERR_NOT_ALLOWLISTED
            ))
        )
        ;; Verify that they're sending enough STX
        (asserts! (>= amount-ustx min-amount-ustx) ERR_INSUFFICIENT_STX)

        (asserts! (<= sats-total allowance) ERR_TOO_MUCH_SATS)

        ;; TODO: add them to the signer set for every cycle of this bond

        ;; TODO: validate caller

        (asserts!
            (map-insert protocol-bond-members {
                bond-index: bond-index,
                staker: tx-sender,
            } {
                amount-sats: sats-total,
                pox-addr: pox-addr,
                reward-per-share-paid: u0,
            })
            ERR_ALREADY_REGISTERED
        )

        (ok true)
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
    (reward-cycle-to-burn-height (+ (var-get first-pox-wf-reward-cycle) (* bond-index BOND_GAP_CYCLES)))
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

(define-read-only (get-bond-allowance
        (bond-index uint)
        (staker principal)
    )
    (map-get? protocol-bond-allowances {
        bond-index: bond-index,
        staker: staker,
    })
)

(define-read-only (get-bond-member
        (bond-index uint)
        (staker principal)
    )
    (map-get? protocol-bond-members {
        bond-index: bond-index,
        staker: staker,
    })
)
