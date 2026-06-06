(define-constant ERR_UNAUTHORIZED (err u1))
(define-constant ERR_CANNOT_SETUP_BOND_TOO_SOON (err u2))
(define-constant ERR_CANNOT_SETUP_BOND_TOO_LATE (err u3))
(define-constant ERR_BOND_ALREADY_SETUP (err u4))
(define-constant ERR_STAKER_ALREADY_ADDED (err u5))
(define-constant ERR_BOND_NOT_FOUND (err u7))
(define-constant ERR_INSUFFICIENT_STX (err u8))
(define-constant ERR_ALREADY_REGISTERED (err u9))
(define-constant ERR_TOO_MUCH_SATS (err u10))
(define-constant ERR_NOT_ALLOWLISTED (err u11))
(define-constant ERR_SIGNER_KEY_GRANT_USED (err u12))
(define-constant ERR_INVALID_SIGNATURE_RECOVER (err u13))
(define-constant ERR_INVALID_SIGNATURE_PUBKEY (err u14))
(define-constant ERR_SIGNER_KEY_GRANT_NOT_FOUND (err u17))
(define-constant ERR_ALREADY_STAKED (err u19))
(define-constant ERR_INVALID_NUM_CYCLES (err u20))
(define-constant ERR_UNAUTHORIZED_CALLER (err u22))
(define-constant ERR_SIGNER_NOT_FOUND (err u23))
(define-constant ERR_INVALID_START_BURN_HEIGHT (err u24))
(define-constant ERR_UNAUTHORIZED_SIGNER_REGISTRATION (err u26))
(define-constant ERR_NOT_STAKING (err u27))
(define-constant ERR_UNSTAKE_IN_PREPARE_PHASE (err u28))
;; Trying to pay out to bonds in an invalid order
(define-constant ERR_INVALID_BOND_PERIOD_ORDERING (err u29))
;; We already calculated at the start of this cycle
(define-constant ERR_DISTRIBUTION_ALREADY_COMPUTED (err u30))
(define-constant ERR_BOND_NOT_ACTIVE (err u31))
(define-constant ERR_NO_CLAIMABLE_REWARDS (err u32))
(define-constant ERR_ACTIVE_BOND_NOT_INCLUDED (err u33))
;; Not actively in a bond
(define-constant ERR_NOT_BOND_PARTICIPANT (err u34))
;; A call to announce an early unlock was made
;; for a bond membership that has an L2 lockup
(define-constant ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK (err u35))
;; The argument provided does not match the staker's signer
(define-constant ERR_INVALID_OLD_SIGNER_MANAGER (err u36))
;; The amount of sats provided to unstake is invalid
(define-constant ERR_INVALID_UNSTAKE_SBTC_AMOUNT (err u37))
;; The bond participant did not stake sBTC
(define-constant ERR_CANNOT_UNSTAKE_SBTC (err u38))
;; A parse error occurred when reading a Bitcoin header
(define-constant ERR_READ_TX_OUT_OF_BOUNDS (err u39))
;; An incorrect Bitcoin header was provided as part of a lockup proof
(define-constant ERR_INVALID_BTC_HEADER (err u40))
;; An incorrect merkle proof was provided as part of a lockup proof
(define-constant ERR_INVALID_MERKLE_PROOF (err u41))
;; The output script provided is incorrect
(define-constant ERR_INVALID_LOCKUP_SCRIPT (err u42))
;; A staker tried to register for a bond after it already started
(define-constant ERR_BOND_ALREADY_STARTED (err u43))
;; Cannot call `update-bond-registration` with the same signer
(define-constant ERR_UPDATE_BOND_SAME_SIGNER (err u44))
;; The lockup amount does not match the specified amount of sats
(define-constant ERR_INVALID_LOCKUP_AMOUNT (err u45))
;; The same Bitcoin outpoint (txid + output-index) appeared twice in
;; the L1 lockup proof list submitted to `register-for-bond`.
(define-constant ERR_DUPLICATE_LOCKUP_OUTPOINT (err u46))
;; A staker tried to modify the next reward cycle's state during the prepare
;; phase.
(define-constant ERR_STAKE_IN_PREPARE_PHASE (err u47))
;; A staker tried to rollover a bond too early
(define-constant ERR_ROLLOVER_TOO_EARLY (err u48))
;; A reentrant call into pox-5 was detected while a signer-manager call was in flight
(define-constant ERR_REENTRANT_CALL (err u49))

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

;; Values for stacks address versions
(define-constant STACKS_ADDR_VERSION_MAINNET 0x16)
(define-constant STACKS_ADDR_VERSION_TESTNET 0x1a)

;; Used to prevent fractional multiplication errors
;; during reward calculations
(define-constant PRECISION u1000000000000000000) ;; 1e18

;; The % of rewards that go to reserve, expressed
;; in basis points
(define-constant RESERVE_RATIO u1500)

;; Core properties of protocol bonds
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
        ;; The OP_ELSE (early-exit) subscript of the L1 lockup witness
        ;; script for this bond period.
        early-unlock-bytes: (buff 683),
        ;; The Stacks principal that can announce early L1 unlocks
        early-unlock-admin: principal,
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
        amount-ustx: uint,
        signer: principal,
        is-l1-lock: bool,
    }
)

;; Total amount of sats staked per bond period
(define-map protocol-bonds-total-staked
    uint
    uint
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

;; Users can stake to a signer, where the signer owner
;; (which is the key of this map) is able to manage
;; the signer key for the signer.
(define-map signers
    principal
    (buff 33) ;; signer key
)

;; Keep track of how much total STX has been delegated for a signer
;; for a given cycle. This includes from both protocol bonds and STX-only
;; stakers. This is the value that should be used to determine signer weight
;; when approving blocks.
(define-map signer-delegated-per-cycle
    {
        signer: principal,
        cycle: uint,
    }
    uint
)

;; Keep track of much much total STX has been staked, only through
;; STX-only signing, for this cycle. This may differ from
;; `signer-shares-staked-for-cycle`, which will be 0 if the total
;; amount delegated to this signer is below `SIGNER_SET_MIN_USTX`.
;;
;; Do not use for reward calculations!
(define-map signer-pending-staked-ustx-per-cycle
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
        signer: principal,
    }
)

;; Per-cycle staker signer membership. Only used for stx-only staking.
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

;; This represents the total uSTX delegated (through both
;; protocol bonds and STX-only staking) for a cycle
(define-map ustx-delegated-per-cycle
    uint
    uint
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

;; State to track the per-share rewards earned for bond periods
;; and reward cycles. This value must only increment
(define-map rewards-per-token-for-cycle
    {
        is-bond: bool,
        index: uint,
    }
    uint
)

;; Total shares (either ustx or sats) staked in a given
;; bond or stx-only cycle
(define-map total-shares-staked-for-cycle
    {
        is-bond: bool,
        index: uint,
    }
    uint
)

;; State to track the per-staker shares for a given signer.
(define-map staker-shares-staked-for-cycle
    {
        is-bond: bool,
        index: uint,
        staker: principal,
        signer: principal,
    }
    uint
)

;; Amount of shares staked for a given signer in a given cycle.
;; This is strictly for reward calculations -
;; i.e. when is-bond is false, only the STX from STX-only staking
;; is accounted for here, not the STX from bonds.
(define-map signer-shares-staked-for-cycle
    {
        is-bond: bool,
        index: uint,
        signer: principal,
    }
    uint
)

;; Represents a snapshot of `rewards-per-token` at the last
;; time of rewards settlement for this specific signer
(define-map signer-rewards-per-token-settled-for-cycle
    {
        is-bond: bool,
        index: uint,
        signer: principal,
    }
    uint
)

;; Represents pending, but unclaimed rewards for a signer
(define-map signer-unclaimed-rewards-for-cycle
    {
        is-bond: bool,
        index: uint,
        signer: principal,
    }
    uint
)

;; Represents a snapshot of `rewards-per-token` at the last
;; time of rewards settlement for this specific staker
(define-map staker-rewards-per-token-settled-for-cycle
    {
        is-bond: bool,
        index: uint,
        signer: principal,
        staker: principal,
    }
    uint
)

;; Represents pending, but unclaimed rewards for a staker
(define-map staker-unclaimed-rewards-for-cycle
    {
        is-bond: bool,
        index: uint,
        signer: principal,
        staker: principal,
    }
    uint
)

(define-map signer-rewards-per-token-for-cycle
    {
        signer: principal,
        is-bond: bool,
        index: uint,
    }
    uint
)

;; The role that is allowed to set bond parameters.
;; On non-mainnet networks `make_pox_5_body` rewrites the literal to the
;; configured admin before deploy.
;; TODO: this should be set to some predefined multisig for mainnet.
(define-data-var bond-admin principal 'SP000000000000000000002Q6VF78)

;; Data vars that store a copy of the burnchain configuration.
;; Implemented as data-vars, so that different configurations can be
;; used in e.g. test harnesses.
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
(define-data-var first-pox-5-reward-cycle uint u0)
;; The first reward cycle where the first bond period occurs
(define-data-var first-bond-period-cycle uint u0)

;; The last accounted balance of rewards. Used to keep
;; track of which sBTC is just for rewards, vs from
;; staking.
(define-data-var last-accounted-rewards-only uint u0)

;; The last burn height in which rewards were calculated
(define-data-var last-reward-compute-height uint u0)

;; the amount of sBTC claimable by the reserve
(define-data-var reserve-balance uint u0)

;; The total amount of sBTC staked
(define-data-var total-sbtc-staked uint u0)

;; Reentrancy guard: prevents cross-function re-entry through signer-manager trait calls
(define-data-var signer-manager-call-active bool false)

(define-trait signer-manager-trait (
    (validate-stake!
        ;; staker, first-index, num-indexes, amount-ustx, amount-sats, is-bond, signer-calldata
        (principal uint uint uint uint bool (optional (buff 500)))
        (response bool uint)
    )
))

(define-private (validate-no-reentrancy)
    (ok (asserts! (not (var-get signer-manager-call-active)) ERR_REENTRANT_CALL))
)

;; A helper function to call the `validate-stake!` function on a given
;; signer-manager, wrapping the reentrancy guard logic around it. This should
;; be the only way that `validate-stake!` is called in the contract, since it
;; is critical to ensure that reentrancy attacks are prevented.
(define-private (signer-manager-validate-stake
        (signer-manager <signer-manager-trait>)
        (staker principal)
        (first-index uint)
        (num-indexes uint)
        (amount-ustx uint)
        (amount-sats uint)
        (is-bond bool)
        (signer-calldata (optional (buff 500)))
    )
    (begin
        (asserts! (not (var-get signer-manager-call-active)) ERR_REENTRANT_CALL)
        (var-set signer-manager-call-active true)
        (try! (contract-call? signer-manager validate-stake! staker first-index
            num-indexes amount-ustx amount-sats is-bond signer-calldata
        ))
        (var-set signer-manager-call-active false)
        (ok true)
    )
)

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
        (var-set first-bond-period-cycle begin-pox5-reward-cycle)
        (var-set configured true)
        (ok true)
    )
)

(define-public (set-bond-admin (new-admin principal))
    (let ((old-admin (var-get bond-admin)))
        ;; only bond admin can call this.
        (asserts! (is-eq contract-caller old-admin) ERR_UNAUTHORIZED)
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))
        (var-set bond-admin new-admin)
        (ok {
            old-admin: old-admin,
            new-admin: new-admin,
        })
    )
)

;; Setup a new protocol bond by providing parameters and the
;; allowlist for the bond.
;;
;; @param bond-index; the index of the bond to set up
;; @param target-rate; target yield rate (apy) in basis points
;; @param stx-value-ratio; representation of STX:BTC price
;; @param min-ustx-ratio; minimum amount of STX that must be locked
;; relative to BTC for this term. Represented in basis points.
;; @param early-unlock-bytes: Bitcoin script that will be used to validate
;; early exit from the bond. It should be of the form
;; `<pubkey> OP_CHECKSIGVERIFY` or an M-of-N `CHECKMULTISIGVERIFY` template.
;; @param early-unlock-admin: The principal that will be allowed to announce
;; early exits from the bond.
;; @param allowlist: A list of allowed stakers and their maximum sats that can
;; be staked for this bond.
;;
;; This function can only be called once for each bond.
(define-public (setup-bond
        (bond-index uint)
        (target-rate uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
        (early-unlock-bytes (buff 683))
        (early-unlock-admin principal)
        (allowlist (list 1000 {
            staker: principal,
            max-sats: uint,
        }))
    )
    (let (
            (bond-start-height (bond-period-to-burn-height bond-index))
            (first-reward-cycle (bond-period-to-reward-cycle bond-index))
            (unlock-cycle (+ first-reward-cycle BOND_LENGTH_CYCLES))
        )
        ;; only bond admin can call this.
        (asserts! (is-eq contract-caller (var-get bond-admin)) ERR_UNAUTHORIZED)

        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; only can be called within 2 cycles of bond start
        (asserts!
            (or
                ;; prevent underflow
                (< bond-start-height
                    (* BOND_GAP_CYCLES (var-get pox-reward-cycle-length))
                )
                (<=
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
                early-unlock-bytes: early-unlock-bytes,
                early-unlock-admin: early-unlock-admin,
            })
            ERR_BOND_ALREADY_SETUP
        )

        (print {
            topic: "setup-bond",
            bond-index: bond-index,
            target-rate: target-rate,
            stx-value-ratio: stx-value-ratio,
            min-ustx-ratio: min-ustx-ratio,
            early-unlock-bytes: early-unlock-bytes,
            early-unlock-admin: early-unlock-admin,
            first-reward-cycle: first-reward-cycle,
            bond-start-height: bond-start-height,
            unlock-cycle: unlock-cycle,
            unlock-burn-height: (reward-cycle-to-burn-height unlock-cycle),
        })

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
                early-unlock-bytes: early-unlock-bytes,
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

;; Register for a protocol bond. In order the call this function,
;; the bond must already have been created, and `contract-caller`
;; must be in the allowlist.
;;
;; The caller must either provide sBTC that they want to lockup,
;; or they must provide proof of their L1 BTC lockup.
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
                    height: uint,
                    tx: (buff 100000),
                    output-index: uint,
                    header: (buff 80),
                    leaf-hashes: (list 14 (buff 32)),
                    tx-count: uint,
                    tx-index: uint,
                    amount: uint,
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
            ;; Compute the sats being staked for this bond.
            (sats-total (try! (match btc-lockup
                l1-lockups (verify-l1-lockups tx-sender bond-index l1-lockups)
                sbtc-amount (ok sbtc-amount)
            )))
            ;; Any bond the staker is currently a member of. Some value here
            ;; means this is a roll-over from an ending bond into a later one.
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock).
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            ;; sBTC this new bond needs custodied (0 on the L1 path).
            (new-sbtc (if (is-ok btc-lockup)
                u0
                sats-total
            ))
            ;; Any STX-only stake the staker has. Present means this
            ;; `register-for-bond` is a roll-over from an ending stx-only
            ;; stake into a bond.
            (existing-stake (map-get? staker-info tx-sender))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (allowance (unwrap!
                (map-get? protocol-bond-allowances {
                    staker: tx-sender,
                    bond-index: bond-index,
                })
                ERR_NOT_ALLOWLISTED
            ))
            (first-reward-cycle (bond-period-to-reward-cycle bond-index))
            (bond-start-height (bond-period-to-burn-height bond-index))
            ;; the first cycle in which their stx are unlocked
            (unlock-cycle (+ first-reward-cycle BOND_LENGTH_CYCLES))
            (current-total-staked (get-total-shares-staked-for-cycle true bond-index))
            (current-signer-staked (get-signer-shares-staked-for-cycle signer true bond-index))
            (stx-balance (stx-account tx-sender))
            (total-balance (+ (get locked stx-balance) (get unlocked stx-balance)))
        )
        (try! (verify-not-prepare-phase))
        ;; Verify that they're sending enough STX
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
        )

        ;; Verify that the bond hasn't started
        (asserts! (< burn-block-height bond-start-height)
            ERR_BOND_ALREADY_STARTED
        )

        ;; An existing STX-only stake is allowed only if its term ends no
        ;; later than this bond's first reward cycle (no overlap). A stx-only
        ;; stake has no L1 collateral, so there's no L1-unlock-window gate
        ;; here -- the lock just extends forward via the node-side handler.
        (asserts!
            (match existing-stake
                stake-info (<=
                    (+ (get first-reward-cycle stake-info)
                        (get num-cycles stake-info)
                    )
                    first-reward-cycle
                )
                true
            )
            ERR_ALREADY_STAKED
        )

        ;; Cannot stake more sats than their allowance
        (asserts! (<= sats-total allowance) ERR_TOO_MUCH_SATS)

        ;; Must have enough unlocked STX
        ;;  the Staker must have sufficient total funds (locked + unlocked).
        ;;  On a roll-over the staker's STX is still locked by the ending
        ;;  bond; the node-side handler extends that lock to the new amount,
        ;;  so checking only `stx-get-balance` (unlocked) would falsely fail.
        (asserts! (>= total-balance amount-ustx) ERR_INSUFFICIENT_STX)

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
            amount-ustx sats-total true signer-calldata
        ))

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

        ;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; Reject if an existing membership *overlaps* this bond. An existing
        ;; bond whose staking term ends no later than this bond's first cycle
        ;; (e.g. rolling from bond N into bond N+6) is allowed.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_REGISTERED
        )

        ;; Settle rewards before updating state
        (settle-rewards signer true bond-index)
        (settle-staker-rewards signer true bond-index tx-sender)

        ;; A rollover from a non-overlapping existing bond may only happen in
        ;; that bond's L1 unlock window, the last 1/2 cycle.
        (try! (verify-bond-rollover-window existing-membership))

        ;; Move the staker's custodied sBTC into this bond, transferring only the
        ;; net difference vs. any bond they're rolling over from.
        (try! (roll-sbtc tx-sender old-sbtc new-sbtc))

        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: amount-ustx,
            signer: signer,
            is-l1-lock: (is-ok btc-lockup),
        })
        (map-set protocol-bonds-total-staked bond-index
            (+ current-total-staked sats-total)
        )
        (map-set total-shares-staked-for-cycle {
            index: bond-index,
            is-bond: true,
        }
            (+ current-total-staked sats-total)
        )
        (map-set signer-shares-staked-for-cycle {
            index: bond-index,
            is-bond: true,
            signer: signer,
        }
            (+ current-signer-staked sats-total)
        )
        (map-set staker-shares-staked-for-cycle {
            index: bond-index,
            is-bond: true,
            staker: tx-sender,
            signer: signer,
        }
            sats-total
        )

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            BOND_LENGTH_CYCLES amount-ustx false
        ))

        ;; If this was a roll-over from an STX-only stake, clear the
        ;; staker-info entry so `stake-update` / `unstake` can no longer
        ;; reach the now-stale stake. The stake's signer-cycle memberships
        ;; through its original term stay intact (the staker keeps
        ;; participating and earning through that term).
        (if (is-some existing-stake)
            (map-delete staker-info tx-sender)
            true
        )

        (let ((result {
                signer: signer,
                staker: tx-sender,
                amount-ustx: amount-ustx,
                sats-total: sats-total,
                bond-index: bond-index,
                first-reward-cycle: first-reward-cycle,
                unlock-burn-height: (reward-cycle-to-burn-height unlock-cycle),
                unlock-cycle: unlock-cycle,
                is-l1-lock: (is-ok btc-lockup),
            }))
            (print (merge { topic: "register-for-bond" } result))
            (ok result)
        )
    )
)

;; As a bond participant, update your signer. This takes effect
;; in the next reward cycle where this bond participant is active.
;;
;; Note that if the bond hasn't started yet, it's possible for the staker
;; to not be active in the next reward cycle. In that case, the signer is updated
;; from the start of the bond period.
(define-public (update-bond-registration
        (signer-manager <signer-manager-trait>)
        (old-signer-manager <signer-manager-trait>)
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            (old-signer (contract-of old-signer-manager))
            (current-membership (unwrap! (get-bond-membership tx-sender) ERR_NOT_BOND_PARTICIPANT))
            (current-signer (get signer current-membership))
            (bond-index (get bond-index current-membership))
            (amount-sats (get-staker-shares-staked-for-cycle tx-sender true bond-index
                current-signer
            ))
            (bond-start-cycle (bond-period-to-reward-cycle bond-index))
            (bond-end-cycle (bond-period-to-reward-cycle (+ bond-index u6)))
            (next-cycle (+ (current-pox-reward-cycle) u1))
            (current-signer-total-sats (get-signer-shares-staked-for-cycle current-signer true bond-index))
            (new-signer-total-sats (get-signer-shares-staked-for-cycle signer true bond-index))
            ;; If the bond hasn't started yet, then the first cycle where
            ;; this new signer is active is the start cycle. Otherwise, it's the next reward
            ;; cycle. In other words, `max(bond-start-cycle, current-cycle + 1)`
            (first-reward-cycle (if (> bond-start-cycle next-cycle)
                bond-start-cycle
                next-cycle
            ))
            (num-cycles (- bond-end-cycle first-reward-cycle))
        )
        (try! (verify-not-prepare-phase))

        ;; Check that the old signer is the current signer
        (asserts! (is-eq old-signer current-signer)
            ERR_INVALID_OLD_SIGNER_MANAGER
        )

        ;; Validate that the new signer is different
        (asserts! (not (is-eq signer old-signer)) ERR_UPDATE_BOND_SAME_SIGNER)

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender bond-index u1
            (get amount-ustx current-membership) amount-sats true
            signer-calldata
        ))

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

        ;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; Settle rewards before mutating related state
        (settle-rewards current-signer true bond-index)
        (settle-rewards signer true bond-index)
        (settle-staker-rewards current-signer true bond-index tx-sender)
        (settle-staker-rewards signer true bond-index tx-sender)

        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender first-reward-cycle num-cycles false))

        ;; Re-add to existing cycles with the new signer
        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            num-cycles (get amount-ustx current-membership) false
        ))

        ;; Remove the sBTC shares from the current signer
        (map-delete staker-shares-staked-for-cycle {
            index: bond-index,
            staker: tx-sender,
            signer: current-signer,
            is-bond: true,
        })
        (map-set signer-shares-staked-for-cycle {
            index: bond-index,
            is-bond: true,
            signer: current-signer,
        }
            (- current-signer-total-sats amount-sats)
        )

        ;; Add the sBTC shares to the current signer
        (map-set staker-shares-staked-for-cycle {
            index: bond-index,
            staker: tx-sender,
            signer: signer,
            is-bond: true,
        }
            amount-sats
        )
        (map-set signer-shares-staked-for-cycle {
            index: bond-index,
            signer: signer,
            is-bond: true,
        }
            (+ new-signer-total-sats amount-sats)
        )
        (map-set protocol-bond-memberships tx-sender {
            bond-index: bond-index,
            amount-ustx: (get amount-ustx current-membership),
            signer: signer,
            is-l1-lock: (get is-l1-lock current-membership),
        })

        (let ((result {
                staker: tx-sender,
                signer: signer,
                old-signer: old-signer,
                bond-index: bond-index,
                amount-ustx: (get amount-ustx current-membership),
                amount-sats: amount-sats,
                first-reward-cycle: first-reward-cycle,
                num-cycles: num-cycles,
                is-l1-lock: (get is-l1-lock current-membership),
            }))
            (print (merge { topic: "update-bond-registration" } result))
            (ok result)
        )
    )
)

;; Register a signer
(define-public (register-signer
        (signer-manager <signer-manager-trait>)
        (signer-key (buff 33))
    )
    (let ((signer (contract-of signer-manager)))
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Because signers can have members register at any time,
        ;; they must use signer key grants instead of per-tx
        ;; authorizations.
        (try! (verify-signer-key-grant signer signer-key))

        ;; Only the signer contract itself can register itself
        (asserts! (is-eq contract-caller signer)
            ERR_UNAUTHORIZED_SIGNER_REGISTRATION
        )

        (map-set signers signer signer-key)
        (let ((result {
                signer: signer,
                signer-key: signer-key,
            }))
            (print (merge { topic: "register-signer" } result))
            (ok result)
        )
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
            ;; Any bond the staker is currently a member of. Some value here
            ;; indicates this `stake` is a roll-over from an ending bond into
            ;; STX-only.
            (existing-membership (map-get? protocol-bond-memberships tx-sender))
            ;; sBTC currently custodied for the staker's existing bond (0 if
            ;; they have none, or if the existing bond is an L1 lock). On a
            ;; bond-to-stake rollover the full custody is refunded below.
            (old-sbtc (get-staker-custodied-sbtc tx-sender))
            (stx-balance (stx-account tx-sender))
            (total-balance (+ (get locked stx-balance) (get unlocked stx-balance)))
        )
        (try! (verify-not-prepare-phase))

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender
            first-reward-cycle num-cycles amount-ustx u0 false
            signer-calldata
        ))

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

        ;; the start-burn-ht must result in the next reward cycle, do not allow stakers
        ;;  to "post-date" their transaction
        (asserts! (is-eq first-reward-cycle specified-reward-cycle)
            ERR_INVALID_START_BURN_HEIGHT
        )

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; Cannot already be STX-only staking. Re-extending an existing stake
        ;; goes through `stake-update`, not a second `stake` call.
        (asserts! (is-none (get-staker-info tx-sender)) ERR_ALREADY_STAKED)

        ;; A roll-over from an existing bond is allowed when the bond's term
        ;; ends no later than this stake's first reward cycle. Already-active
        ;; bonds are rejected (overlap). Same shape as the
        ;; `register-for-bond` gate.
        (asserts!
            (not (bond-overlaps-new-position? existing-membership first-reward-cycle))
            ERR_ALREADY_STAKED
        )

        ;; A roll-over from an ending bond may only happen once that bond's
        ;; L1 collateral would have unlocked -- the same window an L1 bond
        ;; holder has to redirect their BTC. Keeps parity with the
        ;; `register-for-bond` gate so a bond's STX / sBTC can't be released
        ;; ahead of the bond's L1 unlock height.
        (try! (verify-bond-rollover-window existing-membership))

        ;;  the Staker must have sufficient total funds (locked + unlocked).
        ;;  On a roll-over the staker's STX is still locked by the ending
        ;;  bond; the node-side handler extends that lock to the new amount,
        ;;  so checking only `stx-get-balance` (unlocked) would falsely fail.
        (asserts! (>= total-balance amount-ustx) ERR_INSUFFICIENT_STX)

        ;; Refund any sBTC custodied for the rolled-over bond (zero-target
        ;; net transfer). No-op when there is no existing bond, or when the
        ;; existing bond is an L1 lock.
        (try! (roll-sbtc tx-sender old-sbtc u0))

        (try! (add-staker-to-signer-cycles tx-sender signer first-reward-cycle
            num-cycles amount-ustx true
        ))

        (map-set staker-info tx-sender {
            amount-ustx: amount-ustx,
            first-reward-cycle: first-reward-cycle,
            num-cycles: num-cycles,
            signer: signer,
        })

        ;; If this was a roll-over from a bond, clear the bond membership so
        ;; `unstake-sbtc` / `update-bond-registration` can no longer reach
        ;; the old bond. The old bond's reward shares stay through its term;
        ;; only the management pointer is gone.
        (map-delete protocol-bond-memberships tx-sender)

        (let ((result {
                signer: signer,
                staker: tx-sender,
                amount-ustx: amount-ustx,
                num-cycles: num-cycles,
                first-reward-cycle: first-reward-cycle,
                unlock-burn-height: (reward-cycle-to-burn-height unlock-cycle),
                unlock-cycle: unlock-cycle,
            }))
            (print (merge { topic: "stake" } result))
            (ok result)
        )
    )
)

;; A user can:
;; - Change signers
;; - Extend their lock
;; - Increase STX locked
(define-public (stake-update
        (signer-manager <signer-manager-trait>)
        (old-signer-manager <signer-manager-trait>)
        (cycles-to-extend uint)
        (amount-increase uint)
        (signer-calldata (optional (buff 500)))
    )
    (let (
            (signer (contract-of signer-manager))
            (old-signer (contract-of old-signer-manager))
            (current-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKING))
            ;; This is the first cycle where their STX would be unlocked
            (prev-unlock-cycle (+ (get first-reward-cycle current-info)
                (get num-cycles current-info)
            ))
            (unlock-cycle (+ prev-unlock-cycle cycles-to-extend))
            (new-lock-amount (+ (get amount-ustx current-info) amount-increase))
            (current-cycle (current-pox-reward-cycle))
            (first-reward-cycle (+ current-cycle u1))
            (num-cycles (- unlock-cycle current-cycle u1))
        )
        (try! (verify-not-prepare-phase))

        ;; Validate that the staker can join this signer
        (try! (signer-manager-validate-stake signer-manager tx-sender
            first-reward-cycle num-cycles new-lock-amount u0 false
            signer-calldata
        ))

        ;; Validate that `old-signer-manager` matches their current signer
        (asserts! (is-eq old-signer (get signer current-info))
            ERR_INVALID_OLD_SIGNER_MANAGER
        )

        ;; The signer must have been registered already, and its signer key
        ;; grant must still be active.
        (try! (verify-signer-key-grant signer
            (unwrap! (get-signer-info signer) ERR_SIGNER_NOT_FOUND)
        ))

        ;;  lock period must be in acceptable range.
        (asserts! (check-pox-lock-period num-cycles) ERR_INVALID_NUM_CYCLES)

        ;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; Must have enough unlocked STX
        (asserts! (>= (get unlocked (stx-account tx-sender)) amount-increase)
            ERR_INSUFFICIENT_STX
        )

        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender (+ u1 current-cycle)
            (- prev-unlock-cycle current-cycle u1) true
        ))

        (try! (add-staker-to-signer-cycles tx-sender signer (+ u1 current-cycle)
            num-cycles new-lock-amount true
        ))

        (map-set staker-info tx-sender {
            amount-ustx: new-lock-amount,
            first-reward-cycle: (get first-reward-cycle current-info),
            num-cycles: (+ (get num-cycles current-info) cycles-to-extend),
            signer: signer,
        })

        (let ((result {
                unlock-burn-height: (reward-cycle-to-burn-height unlock-cycle),
                staker: tx-sender,
                signer: signer,
                old-signer: old-signer,
                prev-unlock-height: prev-unlock-cycle,
                unlock-cycle: unlock-cycle,
                num-cycles: num-cycles,
                amount-ustx: new-lock-amount,
                amount-increase: amount-increase,
                cycles-to-extend: cycles-to-extend,
            }))
            (print (merge { topic: "stake-update" } result))
            (ok result)
        )
    )
)

(define-public (announce-l1-early-exit
        (staker principal)
        (old-signer-manager <signer-manager-trait>)
    )
    (let (
            (old-signer (contract-of old-signer-manager))
            (membership (unwrap! (get-bond-membership staker) ERR_NOT_BOND_PARTICIPANT))
            (bond-index (get bond-index membership))
            (signer (get signer membership))
            (bond (unwrap-panic (get-protocol-bond bond-index)))
            (amount-sats (get-staker-shares-staked-for-cycle staker true bond-index signer))
            (current-total-shares (get-total-shares-staked-for-cycle true bond-index))
            (current-shares (get-signer-shares-staked-for-cycle signer true bond-index))
        )
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Only the early unlock admin for this bond period can call this function.
        ;; Calling via other contracts is not allowed.
        (asserts!
            (and (is-eq contract-caller tx-sender) (is-eq contract-caller (get early-unlock-admin bond)))
            ERR_UNAUTHORIZED
        )
        (asserts! (get is-l1-lock membership) ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK)
        (asserts! (is-eq old-signer signer) ERR_INVALID_OLD_SIGNER_MANAGER)

        ;; Settle rewards before updating state
        (settle-rewards signer true bond-index)
        (settle-staker-rewards signer true bond-index staker)

        (map-set staker-shares-staked-for-cycle {
            is-bond: true,
            staker: staker,
            signer: signer,
            index: bond-index,
        }
            u0
        )
        (map-set signer-shares-staked-for-cycle {
            is-bond: true,
            signer: signer,
            index: bond-index,
        }
            (- current-shares amount-sats)
        )
        (map-set total-shares-staked-for-cycle {
            index: bond-index,
            is-bond: true,
        }
            (- current-total-shares amount-sats)
        )
        (let ((result {
                staker: staker,
                signer: signer,
                bond-index: bond-index,
                amount-sats-released: amount-sats,
            }))
            (print (merge { topic: "announce-l1-early-exit" } result))
            (ok result)
        )
    )
)

;; As a bond participant with locked sBTC, remove a portion (or all)
;; of your locked sBTC.
(define-public (unstake-sbtc
        (signer-manager <signer-manager-trait>)
        (amount-to-withdrawal-sats uint)
    )
    (let (
            (staker tx-sender)
            (membership (unwrap! (map-get? protocol-bond-memberships staker)
                ERR_NOT_BOND_PARTICIPANT
            ))
            (bond-index (get bond-index membership))
            (signer (get signer membership))
            (current-amount-sats (get-staker-shares-staked-for-cycle staker true bond-index signer))
            (current-total-shares (get-total-shares-staked-for-cycle true bond-index))
            (current-shares (get-signer-shares-staked-for-cycle signer true bond-index))
            (current-total-sbtc-staked (get-total-sbtc-staked))
            ;; Cannot withdrawal more than they've staked
            (new-amount-sats (try! (if (<= amount-to-withdrawal-sats current-amount-sats)

                (ok (- current-amount-sats amount-to-withdrawal-sats))
                ERR_INVALID_UNSTAKE_SBTC_AMOUNT
            )))
        )
        ;; `signer-manager` must match the current signer
        (asserts! (is-eq (contract-of signer-manager) signer)
            ERR_INVALID_OLD_SIGNER_MANAGER
        )

        ;; Must be an sBTC lock
        (asserts! (not (get is-l1-lock membership)) ERR_CANNOT_UNSTAKE_SBTC)

        ;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Take a snapshot of the staker's and signer's current rewards
        (settle-rewards signer true bond-index)
        (settle-staker-rewards signer true bond-index tx-sender)

        (map-set staker-shares-staked-for-cycle {
            is-bond: true,
            staker: staker,
            signer: signer,
            index: bond-index,
        }
            new-amount-sats
        )
        (map-set signer-shares-staked-for-cycle {
            is-bond: true,
            signer: signer,
            index: bond-index,
        }
            (- current-shares amount-to-withdrawal-sats)
        )
        (map-set total-shares-staked-for-cycle {
            is-bond: true,
            index: bond-index,
        }
            (- current-total-shares amount-to-withdrawal-sats)
        )
        (var-set total-sbtc-staked
            (- current-total-sbtc-staked amount-to-withdrawal-sats)
        )

        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" amount-to-withdrawal-sats
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer amount-to-withdrawal-sats tx-sender staker none
            ))
        ))

        (let ((result {
                staker: staker,
                signer: signer,
                bond-index: bond-index,
                amount-withdrawn-sats: amount-to-withdrawal-sats,
                new-amount-sats: new-amount-sats,
            }))
            (print (merge { topic: "unstake-sbtc" } result))
            (ok result)
        )
    )
)

;; Unstake - set your STX to unlock at the end of the current cycle
(define-public (unstake (old-signer-manager <signer-manager-trait>))
    (let (
            (old-signer (contract-of old-signer-manager))
            (current-info (unwrap! (get-staker-info tx-sender) ERR_NOT_STAKING))
            (first-reward-cycle (get first-reward-cycle current-info))
            ;; This is the first cycle where their STX would be unlocked
            (prev-unlock-cycle (+ first-reward-cycle (get num-cycles current-info)))
            (current-cycle (current-pox-reward-cycle))
            (unlock-cycle (+ current-cycle u1))
        )
        (asserts! (is-eq old-signer (get signer current-info))
            ERR_INVALID_OLD_SIGNER_MANAGER
        )
        ;;  must be called directly by the tx-sender or by an allowed contract-caller
        (try! (check-caller-allowed))

        ;; do not allow during a prepare phase
        (asserts! (not (is-in-prepare-phase current-cycle))
            ERR_UNSTAKE_IN_PREPARE_PHASE
        )

        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Remove the staker from all existing cycles
        (try! (remove-staker-from-cycles tx-sender (+ u1 current-cycle)
            (- prev-unlock-cycle current-cycle u1) true
        ))

        (map-set staker-info tx-sender {
            amount-ustx: (get amount-ustx current-info),
            first-reward-cycle: first-reward-cycle,
            num-cycles: (- unlock-cycle first-reward-cycle),
            signer: old-signer,
        })

        (let ((result {
                staker: tx-sender,
                signer: old-signer,
                amount-ustx: (get amount-ustx current-info),
                first-reward-cycle: first-reward-cycle,
                unlock-cycle: unlock-cycle,
                unlock-burn-height: (reward-cycle-to-burn-height unlock-cycle),
            }))
            (print (merge { topic: "unstake" } result))
            (ok result)
        )
    )
)

;;  Remove a staker from a signer for X cycles
(define-private (remove-staker-from-cycles
        (staker principal)
        (first-reward-cycle uint)
        (num-cycles uint)
        (is-stx-staking bool)
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
            is-stx-staking: is-stx-staking,
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
            is-stx-staking: bool,
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
            ;; Get the total uSTX delegated (through protocol bonds and STX-only
            ;; staking) to this signer.
            (cur-delegated-for-signer (get-amount-delegated-for-signer signer cycle))
            ;; uSTX staked for this signer (through STX-only staking)
            (cur-staked-for-signer (get-signer-shares-staked-for-cycle signer false cycle))
            ;; Total uSTX staked (through stx-only staking) this cycle
            (total-shares-staked (get-total-shares-staked-for-cycle false cycle))
            (amount (get amount-ustx membership))
            (is-stx-staking (get is-stx-staking accumulator))
            (stake-amount (if is-stx-staking
                amount
                u0
            ))
            (new-delegated (- cur-delegated-for-signer amount))
            (is-in-signer-set (is-some (get-signer-set-item-for-cycle signer cycle)))
        )
        ;; Settle STX-only rewards before mutating anything
        (settle-rewards signer false cycle)
        (settle-staker-rewards signer false cycle staker)
        (if is-in-signer-set
            (if (< new-delegated SIGNER_SET_MIN_USTX)
                ;; They've crossed back below the threshold - remove from the signer set
                ;; and remove from reward calculations.
                (begin
                    (try! (remove-staker-from-set-for-cycle signer cycle))
                    (map-set signer-shares-staked-for-cycle {
                        index: cycle,
                        signer: signer,
                        is-bond: false,
                    }
                        u0
                    )
                    (map-set total-shares-staked-for-cycle {
                        index: cycle,
                        is-bond: false,
                    }
                        (- total-shares-staked cur-staked-for-signer)
                    )
                )
                ;; They are in the signer set - update reward calculations
                (begin
                    (map-set total-shares-staked-for-cycle {
                        index: cycle,
                        is-bond: false,
                    }
                        (- total-shares-staked stake-amount)
                    )
                    (map-set signer-shares-staked-for-cycle {
                        index: cycle,
                        is-bond: false,
                        signer: signer,
                    }
                        (- cur-staked-for-signer stake-amount)
                    )
                )
            )
            true
        )
        ;; Remove this staker from this signer
        (map-delete staker-signer-cycle-memberships {
            staker: staker,
            cycle: cycle,
        })
        ;; Update amount delegated
        (map-set signer-delegated-per-cycle {
            cycle: cycle,
            signer: signer,
        }
            new-delegated
        )
        ;; Remove amount for staker
        (map-delete staker-shares-staked-for-cycle {
            index: cycle,
            is-bond: false,
            staker: staker,
            signer: signer,
        })
        ;; Update amount staked
        (map-set signer-pending-staked-ustx-per-cycle {
            signer: signer,
            cycle: cycle,
        }
            (- (get-signer-pending-staked-ustx-per-cycle signer cycle)
                stake-amount
            ))
        ;; Update total amount delegated this cycle
        (map-set ustx-delegated-per-cycle cycle
            (- (get-ustx-delegated-for-cycle cycle) amount)
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
        (is-stx-staking bool)
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
            is-stx-staking: is-stx-staking,
        })
    )))
)

;; For a given (staker, signer, cycle), update signer state for that
;; cycle and lazily add the signer to the signer set if needed.
;;
;; We also update state for the total STX delegated to this signer,
;; along with the total of STX staked in STX-only staking for this signer.
;;
;; If the signer is above the minimum threshold, only then do we update
;; reward calculation state, so that signers below the _delegation_ threshold
;; don't receive rewards. This means it's possible for a signer to have
;; _more_ than the minimum delegated, but _less_ staked from STX-only stakers,
;; but they'll still receive rewards.
(define-private (add-staker-to-signer-for-cycle
        (cycle-index uint)
        (accumulator-res (response {
            signer: principal,
            staker: principal,
            amount-ustx: uint,
            first-reward-cycle: uint,
            is-stx-staking: bool,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (cycle (+ cycle-index (get first-reward-cycle accumulator)))
            (signer (get signer accumulator))
            ;; Get the total uSTX delegated (through protocol bonds and STX-only
            ;; staking) to this signer.
            (cur-delegated-for-signer (get-amount-delegated-for-signer signer cycle))
            (amount (get amount-ustx accumulator))
            (stake-amount (if (get is-stx-staking accumulator)
                amount
                u0
            ))
            (staker (get staker accumulator))
            (prev-staked (get-signer-pending-staked-ustx-per-cycle signer cycle))
            (prev-total-shares-staked (get-total-shares-staked-for-cycle false cycle))
            (new-delegated (+ cur-delegated-for-signer amount))
        )
        ;; Crystallize STX-only rewards before mutating anything
        (settle-rewards signer false cycle)
        (settle-staker-rewards signer false cycle staker)
        (if (>= new-delegated SIGNER_SET_MIN_USTX)
            (begin
                (map-set signer-shares-staked-for-cycle {
                    index: cycle,
                    is-bond: false,
                    signer: signer,
                }
                    (+ prev-staked stake-amount)
                )
                (if (< cur-delegated-for-signer SIGNER_SET_MIN_USTX)
                    ;; They just crossed the threshold - add to signer set and add to reward calculations
                    (begin
                        (add-signer-to-set-for-cycle signer cycle)
                        (map-set total-shares-staked-for-cycle {
                            index: cycle,
                            is-bond: false,
                        }
                            (+ prev-total-shares-staked prev-staked stake-amount)
                        )
                    )
                    ;; They're already over the threshold - update the total by just `stake-amount`
                    (map-set total-shares-staked-for-cycle {
                        index: cycle,
                        is-bond: false,
                    }
                        (+ prev-total-shares-staked stake-amount)
                    )
                )
            )

            ;; not over the min yet
            true
        )
        ;; Add the staker's membership
        (map-set staker-signer-cycle-memberships {
            staker: staker,
            cycle: cycle,
        } {
            signer: signer,
            amount-ustx: amount,
        })
        ;; Update the amount delegated
        (map-set signer-delegated-per-cycle {
            cycle: cycle,
            signer: signer,
        }
            new-delegated
        )
        ;; Update the amount staked for this signer
        (map-set signer-pending-staked-ustx-per-cycle {
            signer: signer,
            cycle: cycle,
        }
            (+ prev-staked stake-amount)
        )
        ;; Update the amount staked for this staker
        (map-set staker-shares-staked-for-cycle {
            staker: staker,
            index: cycle,
            is-bond: false,
            signer: signer,
        }
            stake-amount
        )
        ;; Set the total ustx delegated this cycle
        (map-set ustx-delegated-per-cycle cycle
            (+ (get-ustx-delegated-for-cycle cycle) amount)
        )
        ;; Mark settled rewards for this cycle
        (map-set staker-rewards-per-token-settled-for-cycle {
            index: cycle,
            is-bond: false,
            signer: signer,
            staker: staker,
        }
            (get-signer-rewards-per-token-for-cycle signer false cycle)
        )
        (ok accumulator)
    )
)

;; Move a staker's custodied sBTC from `old-sbtc` to `new-sbtc`, transferring
;; only the net difference: pull the increase from the staker, or refund the
;; decrease. `total-sbtc-staked` is updated by the net change. A registration
;; with no rollover passes `old-sbtc` of `u0`, which transfers the full amount.
;; A no-op when the two are equal.
(define-private (roll-sbtc
        (staker principal)
        (old-sbtc uint)
        (new-sbtc uint)
    )
    (begin
        (if (> new-sbtc old-sbtc)
            (let ((delta (- new-sbtc old-sbtc)))
                (try! (contract-call?
                    'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                    transfer delta tx-sender current-contract none
                ))
                (var-set total-sbtc-staked (+ (var-get total-sbtc-staked) delta))
            )
            (if (< new-sbtc old-sbtc)
                (let ((delta (- old-sbtc new-sbtc)))
                    (try! (as-contract?
                        ((with-ft
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            "sbtc-token" delta
                        ))
                        (try! (contract-call?
                            'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                            transfer delta tx-sender staker none
                        ))
                    ))
                    (var-set total-sbtc-staked
                        (- (var-get total-sbtc-staked) delta)
                    )
                )
                ;; new-sbtc == old-sbtc, no transfer needed
                true
            )
        )
        (ok true)
    )
)

;; Verify l1 lockup information for a staker. This asserts that each lockup
;; corresponds to the right timelock script for this staker, and that the lockup
;; occurred on-chain. If everything is valid, this returns the sum of all lockups in sats.
(define-private (verify-l1-lockups
        (staker principal)
        (bond-index uint)
        (lockups {
            outputs: (list 10
                {
                    height: uint,
                    tx: (buff 100000),
                    output-index: uint,
                    header: (buff 80),
                    leaf-hashes: (list 14 (buff 32)),
                    tx-count: uint,
                    tx-index: uint,
                    amount: uint,
                }
            ),
            unlock-bytes: (buff 683),
        })
    )
    (let (
            (bond (unwrap! (get-protocol-bond bond-index) ERR_BOND_NOT_FOUND))
            (expected-timelock-output (construct-lockup-output-script staker
                (get-bond-l1-unlock-height bond-index)
                (get unlock-bytes lockups) (get early-unlock-bytes bond)
            ))
            (accumulation (try! (fold validate-l1-lockup (get outputs lockups)
                (ok {
                    sum: u0,
                    expected-script-hash: expected-timelock-output,
                    seen-outpoints: (list),
                })
            )))
        )
        (ok (get sum accumulation))
    )
)

;; Fold function for validating l1 lockup info
;;
;; - `expected-script-hash` is the timelock script that the lockup must match
;; - `sum` is the running total of sats from all valid lockups processed so far.
;; - `seen-outpoints` tracks every (txid, output-index) pair already credited
;;   in this call. Duplicate entries is rejected via
;;   ERR_DUPLICATE_LOCKUP_OUTPOINT.
(define-private (validate-l1-lockup
        (lockup {
            height: uint,
            tx: (buff 100000),
            output-index: uint,
            header: (buff 80),
            leaf-hashes: (list 14 (buff 32)),
            tx-count: uint,
            tx-index: uint,
            amount: uint,
        })
        (accumulator-res (response {
            expected-script-hash: (buff 34),
            sum: uint,
            seen-outpoints: (list 10 {
                txid: (buff 32),
                output-index: uint,
            }),
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (block (try! (parse-block-header (get header lockup))))
            (expected-script-hash (get expected-script-hash accumulator))
            (output (try! (get-bitcoin-tx-output? (get tx lockup) (get output-index lockup))))
            (reversed-txid (get txid output))
            (txid (reverse-buff32 reversed-txid))
            (outpoint {
                txid: txid,
                output-index: (get output-index lockup),
            })
            (seen-outpoints (get seen-outpoints accumulator))
        )
        (asserts! (verify-block-header (get header lockup) (get height lockup))
            ERR_INVALID_BTC_HEADER
        )
        (asserts! (is-eq (get script output) expected-script-hash)
            ERR_INVALID_LOCKUP_SCRIPT
        )
        (asserts! (is-eq (get amount output) (get amount lockup))
            ERR_INVALID_LOCKUP_AMOUNT
        )
        (asserts! (is-none (index-of? seen-outpoints outpoint))
            ERR_DUPLICATE_LOCKUP_OUTPOINT
        )
        ;; verify merkle proof
        (asserts!
            (or
                (is-eq (get merkle-root block) txid) ;; true, if the transaction is the only transaction
                (verify-merkle-proof reversed-txid
                    (reverse-buff32 (get merkle-root block))
                    (get tx-index lockup) (get tx-count lockup)
                    (get leaf-hashes lockup)
                )
            )
            ERR_INVALID_MERKLE_PROOF
        )
        (ok {
            expected-script-hash: (get expected-script-hash accumulator),
            sum: (+ (get sum accumulator) (get amount output)),
            seen-outpoints: (unwrap-panic (as-max-len? (append seen-outpoints outpoint) u10)),
        })
    )
)

;;; Reward calculation

;; Returns the total balance of rewards received by the contract
(define-read-only (get-rewards)
    (let (
            (cur-reserve (var-get reserve-balance))
            (total-staked-sbtc (get-total-sbtc-staked))
            (current-balance (unwrap-panic (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                get-balance current-contract
            )))
        )
        (- current-balance total-staked-sbtc cur-reserve)
    )
)

;; Returns the total amount of newly received sBTC rewards
;; since the last rewards computation
(define-read-only (get-new-rewards)
    (let (
            (last-accounted-rewards (var-get last-accounted-rewards-only))
            (rewards-balance (get-rewards))
        )
        (- rewards-balance last-accounted-rewards)
    )
)

(define-public (calculate-rewards (bond-periods (list 6 uint)))
    (let (
            (last-calc (var-get last-reward-compute-height))
            (calculation-height (- (distribution-cycle-to-burn-height (current-distribution-cycle))
                u1
            ))
            (cur-reserve (var-get reserve-balance))
            (accrued-rewards (get-new-rewards))
        )
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; verify that we are able to compute here
        (asserts! (> calculation-height last-calc)
            ERR_DISTRIBUTION_ALREADY_COMPUTED
        )

        ;; Verify that all active bonds are included
        (try! (assert-all-active-bonds-included bond-periods calculation-height))

        (let (
                (bond-distributions (try! (fold calculate-bond-rewards bond-periods
                    (ok {
                        last-bond-stx-value-ratio: none,
                        available-rewards: accrued-rewards,
                        last-bond-index: none,
                        calculation-height: calculation-height,
                    })
                )))
                (remaining-rewards (get available-rewards bond-distributions))
                (new-reserve (/ (* remaining-rewards RESERVE_RATIO) u10000))
                (stx-staker-rewards (- remaining-rewards new-reserve))
                (stx-cycle (burn-height-to-reward-cycle calculation-height))
                (cycle-staked-ustx (get-total-shares-staked-for-cycle false stx-cycle))
                (current-rewards-per-ustx (get-rewards-per-token-for-cycle false stx-cycle))
                (prev-accounted-rewards (var-get last-accounted-rewards-only))
                ;; If no STX is staked this cycle, the staker cut will be applied to the reserve.
                (no-stx-stakers (is-eq cycle-staked-ustx u0))
                (new-rewards-per-ustx (if no-stx-stakers
                    u0
                    (/ (* stx-staker-rewards PRECISION) cycle-staked-ustx)
                ))
                (next-rewards-per-ustx (+ current-rewards-per-ustx new-rewards-per-ustx))
                ;; When no STX is staked, fold the staker cut into the reserve, otherwise zero.
                (stranded-staker-cut (if no-stx-stakers
                    stx-staker-rewards
                    u0
                ))
            )
            (print {
                topic: "calculate-rewards",
                bond-periods: bond-periods,
                calculation-height: calculation-height,
                remaining-rewards: remaining-rewards,
                accrued-rewards: accrued-rewards,
                stx-staker-rewards: stx-staker-rewards,
                stx-cycle: stx-cycle,
                cycle-staked-ustx: cycle-staked-ustx,
                next-rewards-per-ustx: next-rewards-per-ustx,
                stranded-staker-cut: stranded-staker-cut,
            })
            (var-set reserve-balance
                (+ cur-reserve new-reserve stranded-staker-cut)
            )
            (var-set last-reward-compute-height calculation-height)
            (var-set last-accounted-rewards-only
                (+ prev-accounted-rewards (- accrued-rewards new-reserve))
            )
            (map-set rewards-per-token-for-cycle {
                index: stx-cycle,
                is-bond: false,
            }
                next-rewards-per-ustx
            )
            (let ((result {
                    bond-periods: bond-periods,
                    calculation-height: calculation-height,
                    remaining-rewards: remaining-rewards,
                    accrued-rewards: accrued-rewards,
                    new-reserve: new-reserve,
                    stx-staker-rewards: stx-staker-rewards,
                    stx-cycle: stx-cycle,
                    cycle-staked-ustx: cycle-staked-ustx,
                    next-rewards-per-ustx: next-rewards-per-ustx,
                }))
                (print (merge { topic: "calculate-rewards" } result))
                (ok result)
            )
        )
    )
)

(define-private (calculate-bond-rewards
        (bond-index uint)
        (accumulator-res (response {
            ;; Used to ensure that the list of bonds are sorted correctly
            last-bond-stx-value-ratio: (optional uint),
            ;; Used as a tie-breaker in the case of bonds with the same
            ;; stx-value-ratio
            last-bond-index: (optional uint),
            ;; How much rewards are available to be distributed
            available-rewards: uint,
            calculation-height: uint,
        }
            uint
        ))
    )
    (let (
            (accumulator (try! accumulator-res))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (total-sats (get-total-shares-staked-for-cycle true bond-index))
            (available-rewards (get available-rewards accumulator))
            ;; How much sBTC the bond is supposed to earn per calculation,
            ;; which is (totalSats * apy) / 50
            (target-yield (/ (/ (* total-sats (get target-rate bond)) u10000) u50))
            ;; If there is enough to cover the target yield, use that. Otherwise,
            ;; this bond gets the remaining rewards.
            (earned (if (>= available-rewards target-yield)
                target-yield
                available-rewards
            ))
            (stx-value-ratio (get stx-value-ratio bond))
            (current-rewards-per-token (get-rewards-per-token-for-cycle true bond-index))
            ;; Prevent divide-by-zero
            (new-rewards-per-token (if (is-eq total-sats u0)
                u0
                (/ (* earned PRECISION) total-sats)
            ))
            (calculation-height (get calculation-height accumulator))
            (bond-start-height (bond-period-to-burn-height bond-index))
            (bond-end-height (bond-period-to-burn-height (+ bond-index u6)))
        )
        ;; Verify that we're paying out bonds in the right order
        (match (get last-bond-stx-value-ratio accumulator)
            last-ratio
            (asserts!
                ;; In a tie-breaker, we still want deterministic results.
                ;; Thus, enforce that the earlier bond period comes first
                (if (is-eq stx-value-ratio last-ratio)
                    ;; Note that < prevents the same bond period from
                    ;; being included twice
                    (> bond-index
                        (unwrap-panic (get last-bond-index accumulator))
                    )
                    (<= stx-value-ratio last-ratio)
                )
                ERR_INVALID_BOND_PERIOD_ORDERING
            )
            ;; When `none`, this is the first bond we're processing
            true
        )

        (map-set rewards-per-token-for-cycle {
            is-bond: true,
            index: bond-index,
        }
            (+ current-rewards-per-token new-rewards-per-token)
        )

        (asserts!
            (and
                (> calculation-height bond-start-height)
                (<= calculation-height bond-end-height)
            )
            ERR_BOND_NOT_ACTIVE
        )

        (print {
            topic: "bond-distribution",
            bond-index: bond-index,
            target-yield: target-yield,
            earned: earned,
        })

        (ok {
            last-bond-stx-value-ratio: (some stx-value-ratio),
            last-bond-index: (some bond-index),
            available-rewards: (- available-rewards earned),
            calculation-height: calculation-height,
        })
    )
)

;; Get the total amount of rewards earned since the last
;; rewards snapshot.
(define-read-only (get-earned
        (signer principal)
        (is-bond bool)
        (index uint)
    )
    (compute-earned-rewards
        (get-signer-shares-staked-for-cycle signer is-bond index)
        (get-rewards-per-token-for-cycle is-bond index)
        (get-signer-rewards-per-token-settled-for-cycle signer is-bond index)
        (get-signer-unclaimed-rewards-for-cycle signer is-bond index)
    )
)

;; Get the total amount of _staker_ rewards earned since the last
;; rewards snapshot.
(define-read-only (get-earned-staker-rewards
        (signer principal)
        (is-bond bool)
        (index uint)
        (staker principal)
    )
    (compute-earned-rewards
        (get-staker-shares-staked-for-cycle staker is-bond index signer)
        (get-signer-rewards-per-token-for-cycle signer is-bond index)
        (get-staker-rewards-per-token-settled-for-cycle signer is-bond index
            staker
        )
        (get-staker-unclaimed-rewards-for-cycle signer is-bond index staker)
    )
)

;; Pure math formula for computing rewards earned since the last snapshot
;;
;; `earned = (shares * (rpt - rptPaid)) / PRECISION + pending`
(define-read-only (compute-earned-rewards
        (shares uint)
        (rpt-current uint)
        (rpt-paid uint)
        (pending uint)
    )
    (+ pending (/ (* shares (- rpt-current rpt-paid)) PRECISION))
)

(define-public (claim-rewards
        (bond-periods (list 6 uint))
        (reward-cycle uint)
    )
    (let (
            (signer contract-caller)
            (stx-rewards (update-claimable-rewards signer false reward-cycle))
            (bond-rewards (fold update-claimable-bond-rewards bond-periods {
                signer: signer,
                total: u0,
                bond-rewards: (list),
            }))
            (bond-totals (get total bond-rewards))
            (total-rewards (+ (get earned stx-rewards) bond-totals))
            (prev-accrued-rewards (var-get last-accounted-rewards-only))
        )
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        (asserts! (> total-rewards u0) ERR_NO_CLAIMABLE_REWARDS)
        (try! (as-contract?
            ((with-ft 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                "sbtc-token" total-rewards
            ))
            (try! (contract-call? 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token
                transfer total-rewards tx-sender signer none
            ))
        ))
        ;; Update contract reward snapshot to prevent issues in next calculation
        (var-set last-accounted-rewards-only
            (- prev-accrued-rewards total-rewards)
        )

        (let ((result {
                stx-rewards: stx-rewards,
                bond-rewards: (get bond-rewards bond-rewards),
                bond-totals: bond-totals,
                total-rewards: total-rewards,
            }))
            (print (merge { topic: "claim-rewards" } result))
            (ok result)
        )
    )
)

;; As a signer manager contract, mark a specific staker as having claimed
;; rewards. This is used to mutate internal rewards settlement state.
;;
;; This is only callable by the signer manager contract.
(define-public (claim-staker-rewards-for-signer
        (staker principal)
        (is-bond bool)
        (index uint)
    )
    (let ((rewards-info (settle-staker-rewards contract-caller is-bond index staker)))
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))
        (map-set staker-unclaimed-rewards-for-cycle {
            is-bond: is-bond,
            index: index,
            signer: contract-caller,
            staker: staker,
        }
            u0
        )
        (ok rewards-info)
    )
)

;; For the provided args, calculate the total newly claimable rewards for the signer.
;; Then, update state to reflect this amount as claimed.
;;
;; Returns the newly claimable amount. Does NOT transfer funds out.
(define-private (update-claimable-rewards
        (signer principal)
        (is-bond bool)
        (index uint)
    )
    (let ((earned (settle-rewards signer is-bond index)))
        ;; After crystallization, all earnings live in pending.
        ;; Zero out pending since we're about to pay it.
        (map-set signer-unclaimed-rewards-for-cycle {
            is-bond: is-bond,
            index: index,
            signer: signer,
        }
            u0
        )
        earned
    )
)

(define-private (update-claimable-bond-rewards
        (bond-index uint)
        (accumulator {
            signer: principal,
            total: uint,
            bond-rewards: (list 6
                {
                    earned: uint,
                    bond-index: uint,
                    rewards-per-token: uint,
                }
            ),
        })
    )
    (let ((rewards-info (update-claimable-rewards (get signer accumulator) true bond-index)))
        {
            signer: (get signer accumulator),
            total: (+ (get total accumulator) (get earned rewards-info)),
            bond-rewards: (concat
                (unwrap-panic (as-max-len? (get bond-rewards accumulator) u5))
                (list (merge rewards-info { bond-index: bond-index }))
            ),
        }
    )
)

;; Update all earned-but-unclaimed rewards for a signer, and update the snapshot
;; (signer-rewards-per-token-settled-for-cycle) for the signer.
;;
;; This MUST be called before any update to `signer-shares-staked-for-cycle`,
;; because changes to that state will effect rewards calculations.
(define-private (settle-rewards
        (signer principal)
        (is-bond bool)
        (index uint)
    )
    (let (
            (earned (get-earned signer is-bond index))
            (rewards-per-token (get-rewards-per-token-for-cycle is-bond index))
        )
        (map-set signer-unclaimed-rewards-for-cycle {
            is-bond: is-bond,
            index: index,
            signer: signer,
        }
            earned
        )
        (map-set signer-rewards-per-token-settled-for-cycle {
            is-bond: is-bond,
            index: index,
            signer: signer,
        }
            rewards-per-token
        )
        (if (> (get-signer-shares-staked-for-cycle signer is-bond index) u0)
            (map-set signer-rewards-per-token-for-cycle {
                signer: signer,
                index: index,
                is-bond: is-bond,
            }
                rewards-per-token
            )
            true
        )
        {
            earned: earned,
            rewards-per-token: rewards-per-token,
        }
    )
)

;; Update all earned-but-unclaimed rewards for a staker, and update the snapshot
;; (staker-rewards-per-token-settled-for-cycle) for the staker.
;;
;; This MUST be called before any update to `staker-shares-staked-for-cycle`,
;; because changes to that state will effect rewards calculations.
(define-private (settle-staker-rewards
        (signer principal)
        (is-bond bool)
        (index uint)
        (staker principal)
    )
    (let (
            (earned (get-earned-staker-rewards signer is-bond index staker))
            (rewards-per-token (get-signer-rewards-per-token-for-cycle signer is-bond index))
        )
        (map-set staker-unclaimed-rewards-for-cycle {
            is-bond: is-bond,
            index: index,
            signer: signer,
            staker: staker,
        }
            earned
        )
        (map-set staker-rewards-per-token-settled-for-cycle {
            is-bond: is-bond,
            index: index,
            signer: signer,
            staker: staker,
        }
            rewards-per-token
        )
        {
            earned: earned,
            rewards-per-token: rewards-per-token,
        }
    )
)

(define-read-only (assert-all-active-bonds-included
        (bond-periods (list 6 uint))
        (calculation-height uint)
    )
    (let (
            (calc-cycle (burn-height-to-reward-cycle calculation-height))
            (first-bond-cycle (var-get first-bond-period-cycle))
            (latest-bond-index (if (<= calc-cycle first-bond-cycle)
                u0
                (/ (- calc-cycle first-bond-cycle) BOND_GAP_CYCLES)
            ))
        )
        (try! (fold assert-active-bond-included (list u0 u1 u2 u3 u4 u5)
            (ok {
                latest-bond-index: latest-bond-index,
                calculation-height: calculation-height,
                bond-periods: bond-periods,
            })
        ))
        (ok true)
    )
)

(define-private (assert-active-bond-included
        (offset uint)
        (acc-res (response {
            latest-bond-index: uint,
            calculation-height: uint,
            bond-periods: (list 6 uint),
        }
            uint
        ))
    )
    (let (
            (acc (try! acc-res))
            (latest-bond-index (get latest-bond-index acc))
        )
        (if (> offset latest-bond-index)
            (ok acc)
            (let ((bond-index (- latest-bond-index offset)))
                (if (is-bond-active-at-height bond-index
                        (get calculation-height acc)
                    )
                    (begin
                        (asserts!
                            (get found
                                (fold match-uint-in-list (get bond-periods acc) {
                                    needle: bond-index,
                                    found: false,
                                })
                            )
                            ERR_ACTIVE_BOND_NOT_INCLUDED
                        )
                        (ok acc)
                    )
                    (ok acc)
                )
            )
        )
    )
)

;; helper to check if a list contains a value
(define-private (match-uint-in-list
        (item uint)
        (acc {
            needle: uint,
            found: bool,
        })
    )
    {
        needle: (get needle acc),
        found: (or (get found acc) (is-eq item (get needle acc))),
    }
)

;; TODO: private fn to transfer funds from reserve
;; (define-private (transfer-from-reserve (amount uint) (recipient uint)))

;;; Signer key authorization functions

(define-public (grant-signer-key
        (signer-key (buff 33))
        (signer-manager principal)
        (auth-id uint)
        (signer-sig (buff 65))
    )
    (begin
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

        ;; Only the signer contract itself can call this function to grant a signer key
        (asserts! (is-eq contract-caller signer-manager)
            ERR_UNAUTHORIZED_SIGNER_REGISTRATION
        )
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

        (ok {
            signer-key: signer-key,
            signer-manager: signer-manager,
            auth-id: auth-id,
        })
    )
)

;; Revoke a signer key grant for a staker. Only the Stacks principal
;; associated with `signer-key` can call this function.
;;
;; Revoking has two effects: it prevents future `register-signer` calls for
;; this (signer-key, signer-manager) pair, and, because every new-stake
;; entry point re-checks the grant via `verify-signer-key-grant`, it also
;; disables an already-registered manager from accepting any new stake. The
;; manager's `signers` entry is left intact so its outstanding obligations can
;; still be settled; those positions wind down as their bonds/stakes expire.
;;
;; Returns a boolean indicating whether the signer key grant existed.
(define-public (revoke-signer-grant
        (signer-manager principal)
        (signer-key (buff 33))
    )
    (begin
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

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
        (ok {
            signer-key: signer-key,
            signer-manager: signer-manager,
            existed: (map-delete signer-key-grants {
                signer-key: signer-key,
                signer-manager: signer-manager,
            }),
        })
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

;; What's the burn height at the start of a given bond index?
(define-read-only (bond-period-to-burn-height (bond-index uint))
    (reward-cycle-to-burn-height (bond-period-to-reward-cycle bond-index))
)

;; What reward cycle does a bond index start at?
(define-read-only (bond-period-to-reward-cycle (bond-index uint))
    (+ (var-get first-bond-period-cycle) (* bond-index BOND_GAP_CYCLES))
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

;; What's the current PoX reward cycle?
(define-read-only (current-pox-reward-cycle)
    (burn-height-to-reward-cycle burn-block-height)
)

;; At a given burn height, what distribution cycle are we in?
;; This is zero-indexed at the first reward-cycle
(define-read-only (burn-height-to-distribution-index (height uint))
    (/ (- height (var-get first-burnchain-block-height))
        (/ (var-get pox-reward-cycle-length) u2)
    )
)

;; What's the current distribution cycle?
(define-read-only (current-distribution-cycle)
    (burn-height-to-distribution-index burn-block-height)
)

;; The start burn height of a given distribution cycle
(define-read-only (distribution-cycle-to-burn-height (cycle uint))
    (+ (var-get first-burnchain-block-height)
        (* cycle (/ (var-get pox-reward-cycle-length) u2))
    )
)

;; Are we currently in a prepare phase at the end of `current-cycle`?
(define-read-only (is-in-prepare-phase (current-cycle uint))
    (>= burn-block-height
        (- (reward-cycle-to-burn-height (+ current-cycle u1))
            (var-get pox-prepare-cycle-length)
        ))
)

;; Reject calls that would modify the next reward cycle's signer / staker
;; set during the current cycle's prepare phase, when that set is frozen.
;; Used by `stake`, `stake-update`, `register-for-bond`, and
;; `update-bond-registration` as `(try! (verify-not-prepare-phase))`.
(define-private (verify-not-prepare-phase)
    (ok (asserts! (not (is-in-prepare-phase (current-pox-reward-cycle)))
        ERR_STAKE_IN_PREPARE_PHASE
    ))
)

;; The sBTC the staker currently has custodied in pox-5, derived from their
;; bond membership. Returns u0 when the staker has no bond membership, or
;; when their existing bond is an L1 lock (no sBTC is custodied for L1
;; bonds). Used by `register-for-bond` and `stake` to compute the source
;; side of a `roll-sbtc` net transfer.
(define-read-only (get-staker-custodied-sbtc (staker principal))
    (match (map-get? protocol-bond-memberships staker)
        m (if (get is-l1-lock m)
            u0
            (get-staker-shares-staked-for-cycle staker true (get bond-index m)
                (get signer m)
            )
        )
        u0
    )
)

;; True if `existing-membership` (when present) would overlap a new staking
;; term starting at `new-first-reward-cycle`. A bond whose term ends at or
;; before the new first cycle is non-overlapping. Callers wrap this in
;; their own `asserts!` so they can pick the appropriate error code
;; (`ERR_ALREADY_REGISTERED` in `register-for-bond`, `ERR_ALREADY_STAKED`
;; in `stake`).
(define-read-only (bond-overlaps-new-position?
        (existing-membership (optional {
            bond-index: uint,
            amount-ustx: uint,
            signer: principal,
            is-l1-lock: bool,
        }))
        (new-first-reward-cycle uint)
    )
    (match existing-membership
        existing (>
            (+ BOND_LENGTH_CYCLES
                (bond-period-to-reward-cycle (get bond-index existing))
            )
            new-first-reward-cycle
        )
        false
    )
)

;; Reject a rollover attempt before the existing bond's L1 collateral would
;; have unlocked -- same window an L1 bond holder has to redirect their
;; BTC. No-op when there is no existing bond. Used by `register-for-bond`
;; and `stake` as `(try! (verify-bond-rollover-window existing-membership))`,
;; same shape as `verify-not-prepare-phase`.
(define-private (verify-bond-rollover-window (existing-membership (optional {
    bond-index: uint,
    amount-ustx: uint,
    signer: principal,
    is-l1-lock: bool,
})))
    (ok (asserts!
        (match existing-membership
            existing (>= burn-block-height
                (get-bond-l1-unlock-height (get bond-index existing))
            )
            true
        )
        ERR_ROLLOVER_TOO_EARLY
    ))
)

(define-read-only (is-bond-active-at-height
        (bond-index uint)
        (calculation-height uint)
    )
    (let (
            (bond-start-height (bond-period-to-burn-height bond-index))
            (bond-end-height (bond-period-to-burn-height (+ bond-index u6)))
        )
        (and
            (is-some (map-get? protocol-bonds bond-index))
            (> calculation-height bond-start-height)
            (<= calculation-height bond-end-height)
        )
    )
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
        info
        (if (<= (+ (get first-reward-cycle info) (get num-cycles info))
                (current-pox-reward-cycle)
            )
            ;; present, but lock has expired
            none
            ;; present, and lock has not expired
            (some info)
        )
        ;; no state at all
        none
    )
)

(define-read-only (get-signer-info (signer principal))
    (map-get? signers signer)
)

;; Get the total uSTX delegated (through protocol bonds and STX-only
;; staking) to this signer.
(define-read-only (get-amount-delegated-for-signer
        (signer principal)
        (cycle uint)
    )
    (default-to u0
        (map-get? signer-delegated-per-cycle {
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

(define-read-only (get-total-sbtc-staked-for-bond (bond-index uint))
    (default-to u0 (map-get? protocol-bonds-total-staked bond-index))
)

(define-read-only (get-rewards-per-token-for-cycle
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? rewards-per-token-for-cycle {
            is-bond: is-bond,
            index: index,
        })
    )
)

(define-read-only (get-total-shares-staked-for-cycle
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? total-shares-staked-for-cycle {
            is-bond: is-bond,
            index: index,
        })
    )
)

(define-read-only (get-signer-shares-staked-for-cycle
        (signer principal)
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? signer-shares-staked-for-cycle {
            is-bond: is-bond,
            index: index,
            signer: signer,
        })
    )
)

;; Get the amount of shares staked for a given staker in a certain cycle.
(define-read-only (get-staker-shares-staked-for-cycle
        (staker principal)
        (is-bond bool)
        (index uint)
        (signer principal)
    )
    (default-to u0
        (map-get? staker-shares-staked-for-cycle {
            index: index,
            staker: staker,
            is-bond: is-bond,
            signer: signer,
        })
    )
)

(define-read-only (get-signer-rewards-per-token-settled-for-cycle
        (signer principal)
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? signer-rewards-per-token-settled-for-cycle {
            signer: signer,
            is-bond: is-bond,
            index: index,
        })
    )
)

(define-read-only (get-signer-unclaimed-rewards-for-cycle
        (signer principal)
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? signer-unclaimed-rewards-for-cycle {
            signer: signer,
            is-bond: is-bond,
            index: index,
        })
    )
)

(define-read-only (get-staker-rewards-per-token-settled-for-cycle
        (signer principal)
        (is-bond bool)
        (index uint)
        (staker principal)
    )
    (default-to u0
        (map-get? staker-rewards-per-token-settled-for-cycle {
            staker: staker,
            signer: signer,
            is-bond: is-bond,
            index: index,
        })
    )
)

(define-read-only (get-staker-unclaimed-rewards-for-cycle
        (signer principal)
        (is-bond bool)
        (index uint)
        (staker principal)
    )
    (default-to u0
        (map-get? staker-unclaimed-rewards-for-cycle {
            staker: staker,
            signer: signer,
            is-bond: is-bond,
            index: index,
        })
    )
)

(define-read-only (get-signer-rewards-per-token-for-cycle
        (signer principal)
        (is-bond bool)
        (index uint)
    )
    (default-to u0
        (map-get? signer-rewards-per-token-for-cycle {
            signer: signer,
            is-bond: is-bond,
            index: index,
        })
    )
)

(define-read-only (get-signer-pending-staked-ustx-per-cycle
        (signer principal)
        (cycle uint)
    )
    (default-to u0
        (map-get? signer-pending-staked-ustx-per-cycle {
            signer: signer,
            cycle: cycle,
        })
    )
)

(define-read-only (get-last-reward-compute-height)
    (var-get last-reward-compute-height)
)

(define-read-only (get-reserve-balance)
    (var-get reserve-balance)
)

(define-read-only (get-total-sbtc-staked)
    (var-get total-sbtc-staked)
)

(define-read-only (get-last-accounted-rewards-only)
    (var-get last-accounted-rewards-only)
)

(define-read-only (get-ustx-delegated-for-cycle (reward-cycle uint))
    (default-to u0 (map-get? ustx-delegated-per-cycle reward-cycle))
)

;; How many uSTX are staked? - Required to be named this to
;; work with `chainstate.get_total_ustx_stacked`
(define-read-only (get-total-ustx-stacked (reward-cycle uint))
    (get-ustx-delegated-for-cycle reward-cycle)
)

(define-read-only (check-pox-lock-period (lock-period uint))
    (and
        (>= lock-period u1)
        (<= lock-period MAX_NUM_CYCLES)
    )
)

(define-read-only (get-protocol-bond (bond-index uint))
    (map-get? protocol-bonds bond-index)
)

;; Returns the expected L1 unlock height for a given bond index.
;; This is equal to 1/2 of a reward cycle before the end of the bond period.
(define-read-only (get-bond-l1-unlock-height (bond-index uint))
    (- (bond-period-to-burn-height (+ bond-index u6))
        (/ (var-get pox-reward-cycle-length) u2)
    )
)

(define-read-only (get-first-pox-5-reward-cycle)
    (var-get first-pox-5-reward-cycle)
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
                expiration (< burn-block-height expiration)
                true
            )
        )
        ERR_UNAUTHORIZED_CALLER
    ))
)

;; Revoke contract-caller authorization to call stacking methods
(define-public (disallow-contract-caller (caller principal))
    (begin
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

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
        ;; ensure no reentrancy through signer-manager trait calls
        (try! (validate-no-reentrancy))

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
(define-map signer-set-ll-first-for-cycle
    uint
    principal
)
;; Last item in the linked list of stakers
(define-map signer-set-ll-last-for-cycle
    uint
    principal
)

;; Linked list of all stakers for a cycle
(define-map signer-set-ll-for-cycle
    {
        cycle: uint,
        signer: principal,
    }
    {
        prev: (optional principal),
        next: (optional principal),
    }
)

(define-read-only (get-signer-set-last-item-for-cycle (cycle uint))
    (map-get? signer-set-ll-last-for-cycle cycle)
)

(define-read-only (get-signer-set-first-item-for-cycle (cycle uint))
    (map-get? signer-set-ll-first-for-cycle cycle)
)

(define-read-only (get-signer-set-item-for-cycle
        (signer principal)
        (cycle uint)
    )
    (map-get? signer-set-ll-for-cycle {
        cycle: cycle,
        signer: signer,
    })
)

(define-read-only (get-signer-set-next-item-for-cycle
        (signer principal)
        (cycle uint)
    )
    (match (map-get? signer-set-ll-for-cycle {
        cycle: cycle,
        signer: signer,
    })
        item (get next item)
        none
    )
)

(define-read-only (get-signer-set-prev-item-for-cycle
        (signer principal)
        (cycle uint)
    )
    (match (map-get? signer-set-ll-for-cycle {
        cycle: cycle,
        signer: signer,
    })
        item (get prev item)
        none
    )
)

(define-read-only (signer-set-contains-for-cycle
        (signer principal)
        (cycle uint)
    )
    (is-some (map-get? signer-set-ll-for-cycle {
        cycle: cycle,
        signer: signer,
    }))
)

(define-private (add-signer-to-set-for-cycle
        (signer principal)
        (cycle uint)
    )
    (let ((last-item (map-get? signer-set-ll-last-for-cycle cycle)))
        (match last-item
            last-signer (let ((last-node (unwrap-panic (map-get? signer-set-ll-for-cycle {
                    cycle: cycle,
                    signer: last-signer,
                }))))
                (map-set signer-set-ll-for-cycle {
                    cycle: cycle,
                    signer: last-signer,
                } {
                    prev: (get prev last-node),
                    next: (some signer),
                })
                (map-set signer-set-ll-for-cycle {
                    cycle: cycle,
                    signer: signer,
                } {
                    prev: (some last-signer),
                    next: none,
                })
            )
            (begin
                ;; This is the first item
                (map-set signer-set-ll-for-cycle {
                    cycle: cycle,
                    signer: signer,
                } {
                    prev: none,
                    next: none,
                })
                (map-set signer-set-ll-first-for-cycle cycle signer)
            )
        )

        (map-set signer-set-ll-last-for-cycle cycle signer)
    )
)

(define-private (remove-staker-from-set-for-cycle
        (signer principal)
        (cycle uint)
    )
    (let (
            (node (unwrap!
                (map-get? signer-set-ll-for-cycle {
                    cycle: cycle,
                    signer: signer,
                })
                ERR_NOT_STAKING
            ))
            (prev-item (get prev node))
            (next-item (get next node))
        )
        (match prev-item
            prev-signer
            (map-set signer-set-ll-for-cycle {
                cycle: cycle,
                signer: prev-signer,
            } {
                prev: (get prev
                    (unwrap-panic (map-get? signer-set-ll-for-cycle {
                        signer: prev-signer,
                        cycle: cycle,
                    }))
                ),
                next: next-item,
            })
            ;; this is the first item
            (match next-item
                next
                (map-set signer-set-ll-first-for-cycle cycle next)
                ;; no previous or next - this is the only item
                (begin
                    (map-delete signer-set-ll-last-for-cycle cycle)
                    (map-delete signer-set-ll-first-for-cycle cycle)
                )
            )
        )

        (match next-item
            next-signer (map-set signer-set-ll-for-cycle {
                cycle: cycle,
                signer: next-signer,
            } {
                prev: prev-item,
                next: (get next
                    (unwrap-panic (map-get? signer-set-ll-for-cycle {
                        signer: next-signer,
                        cycle: cycle,
                    }))
                ),
            })
            (match prev-item
                prev-signer
                (map-set signer-set-ll-last-for-cycle cycle prev-signer)
                ;; This is the only item - we've already handled this, though
                true
            )
        )
        (map-delete signer-set-ll-for-cycle {
            cycle: cycle,
            signer: signer,
        })
        (ok true)
    )
)

;;; Clarity-Bitcoin helpers

;; Parse a Bitcoin block header.
;; Returns a tuple structured as folowed on success:
;; (ok {
;;      version: uint,                  ;; block version,
;;      parent: (buff 32),              ;; parent block hash,
;;      merkle-root: (buff 32),         ;; merkle root for all this block's transactions
;;      timestamp: uint,                ;; UNIX epoch timestamp of this block, in seconds
;;      nbits: uint,                    ;; compact block difficulty representation
;;      nonce: uint                     ;; PoW solution
;; })
(define-read-only (parse-block-header (headerbuff (buff 80)))
    (let (
            (ctx {
                txbuff: headerbuff,
                index: u0,
            })
            (parsed-version (try! (read-uint32 ctx)))
            (parsed-parent-hash (try! (read-hashslice (get ctx parsed-version))))
            (parsed-merkle-root (try! (read-hashslice (get ctx parsed-parent-hash))))
            (parsed-timestamp (try! (read-uint32 (get ctx parsed-merkle-root))))
            (parsed-nbits (try! (read-uint32 (get ctx parsed-timestamp))))
            (parsed-nonce (try! (read-uint32 (get ctx parsed-nbits))))
        )
        (ok {
            version: (get uint32 parsed-version),
            parent: (get hashslice parsed-parent-hash),
            merkle-root: (get hashslice parsed-merkle-root),
            timestamp: (get uint32 parsed-timestamp),
            nbits: (get uint32 parsed-nbits),
            nonce: (get uint32 parsed-nonce),
        })
    )
)

;; Reads the next four bytes from txbuff as a little-endian 32-bit integer, and updates the index.
;; Returns (ok { uint32: uint, ctx: { txbuff: (buff 4096), index: uint } }) on success.
;; Returns ERR_READ_TX_OUT_OF_BOUNDS if we read past the end of txbuff
(define-read-only (read-uint32 (ctx {
    txbuff: (buff 4096),
    index: uint,
}))
    (let (
            (data (get txbuff ctx))
            (base (get index ctx))
        )
        (ok {
            uint32: (buff-to-uint-le (unwrap-panic (as-max-len?
                (unwrap! (slice? data base (+ base u4)) ERR_READ_TX_OUT_OF_BOUNDS)
                u4
            ))),
            ctx: {
                txbuff: data,
                index: (+ u4 base),
            },
        })
    )
)

;; Reads a little-endian hash -- consume the next 32 bytes, and reverse them.
;; Returns (ok { hashslice: (buff 32), ctx: { txbuff: (buff 4096), index: uint } }) on success, and updates the index.
;; Returns ERR_READ_TX_OUT_OF_BOUNDS if we read past the end of txbuff.
(define-read-only (read-hashslice (old-ctx {
    txbuff: (buff 4096),
    index: uint,
}))
    (let (
            (slice-start (get index old-ctx))
            (target-index (+ u32 slice-start))
            (txbuff (get txbuff old-ctx))
            (hash-le (unwrap-panic (as-max-len?
                (unwrap! (slice? txbuff slice-start target-index)
                    ERR_READ_TX_OUT_OF_BOUNDS
                )
                u32
            )))
        )
        (ok {
            hashslice: (reverse-buff32 hash-le),
            ctx: {
                txbuff: txbuff,
                index: target-index,
            },
        })
    )
)

(define-read-only (reverse-buff32 (input (buff 32)))
    (unwrap-panic (as-max-len?
        (concat
            (reverse-buff16 (unwrap-panic (as-max-len? (unwrap-panic (slice? input u16 u32)) u16)))
            (reverse-buff16 (unwrap-panic (as-max-len? (unwrap-panic (slice? input u0 u16)) u16)))
        )
        u32
    ))
)

(define-private (reverse-buff16 (input (buff 16)))
    (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? (buff-to-uint-le input))) u1 u17))
)
(define-read-only (get-bc-h-hash (bh uint))
    (get-burn-block-info? header-hash bh)
)

;; Verify that a block header hashes to a burnchain header hash at a given height.
;; Returns true if so; false if not.
(define-read-only (verify-block-header
        (headerbuff (buff 80))
        (expected-block-height uint)
    )
    (match (get-burn-block-info? header-hash expected-block-height)
        bhh (is-eq bhh (reverse-buff32 (sha256 (sha256 headerbuff))))
        false
    )
)

;; Get the txid of a transaction, but little-endian.
;; This is the reverse of what you see on block explorers.
(define-read-only (get-reversed-txid (tx (buff 100000)))
    (sha256 (sha256 tx))
)

;;; Lock script helpers

;; Contruct an L1 lockup script.
;;
;; `unlock-bytes` and `early-unlock-bytes` are caller-supplied Bitcoin
;; Script *subscripts*. `unlock-bytes` should be a subscript that validates the
;; signature of the staker (e.g., `<pubkey> OP_CHECKSIG` or an M-of-N
;; `CHECKMULTISIG` template). It MUST leave a valid result on the stack.
;; `early-unlock-bytes` should be a subscript that validates the signature of
;; the early unlock admin and MUST NOT leave anything on the stack (e.g.
;; `<pubkey> OP_CHECKSIGVERIFY`, or an M-of-N `CHECKMULTISIGVERIFY` template).
;;
;; The constructed script has this structure:
;; ```
;; <staker> OP_DROP
;; OP_IF
;;     <unlock-burn-height> OP_CHECKLOCKTIMEVERIFY OP_DROP
;;     <unlock-bytes>
;; OP_ELSE
;;     <early-unlock-bytes>
;;     <unlock-bytes>
;; OP_ENDIF
;; ```
(define-read-only (construct-lockup-script
        (staker principal)
        (unlock-burn-height uint)
        (unlock-bytes (buff 683))
        (early-unlock-bytes (buff 683))
    )
    (concat (push-script-bytes (unwrap-panic (to-consensus-buff? staker)))
        (concat 0x7563 ;; OP_DROP, OP_IF
            (concat (push-c-script-num unlock-burn-height)
                (concat 0xb175 ;; OP_CHECKLOCKTIMEVERIFY, OP_DROP
                    (concat unlock-bytes
                        (concat 0x67 ;; OP_ELSE
                            (concat early-unlock-bytes
                                (concat unlock-bytes 0x68
                                    ;; OP_ENDIF
                                ))
                        ))
                ))
        ))
)

;; Construct the p2wsh output script for a L1 lockup address
(define-read-only (construct-lockup-output-script
        (staker principal)
        (unlock-burn-height uint)
        (unlock-bytes (buff 683))
        (early-unlock-bytes (buff 683))
    )
    (concat 0x0020
        (sha256 (construct-lockup-script staker unlock-burn-height unlock-bytes
            early-unlock-bytes
        ))
    )
)

;; Convert a u8 or u16 to a little-endian byte buffer,
;; ONLY FOR n <= 0xffff (or it will panic).
(define-read-only (uint-to-buff-le (n uint))
    (let (
            (bounds-check_ (unwrap-panic (if (<= n u65535)
                (some true)
                none
            )))
            (bytes (unwrap-panic (to-consensus-buff? n)))
            (lsb (unwrap-panic (slice? bytes u16 u17)))
        )
        (unwrap-panic (as-max-len?
            (if (< n u256)
                lsb
                (concat lsb (unwrap-panic (slice? bytes u15 u16)))
            )
            u2
        ))
    )
)

;; Construct the correct script for pushing bytes into a Bitcoin script.
;;
;; If len < 76, just push the length
;; If len < 256, push PUSHDATA1, then the little-endian length
;; If len < 65535 (0xffff), push PUSHDATA2, then the U16LE-encoded length
(define-read-only (push-script-bytes (bytes (buff 1024)))
    (let ((byte-length (len bytes)))
        (concat
            (if (< byte-length u76)
                (uint-to-buff-le byte-length)
                (if (< byte-length u256)
                    (concat 0x4c (uint-to-buff-le byte-length))
                    (concat 0x4d (uint-to-buff-le byte-length))
                )
            )
            bytes
        )
    )
)

(define-read-only (serialize-c-script-num (n uint))
    (unwrap-panic (as-max-len?
        (if (is-eq n u0)
            0x
            (let (
                    (bytes (unwrap-panic (to-consensus-buff? n)))
                    (b0 (unwrap-panic (slice? bytes u16 u17)))
                    (b1 (unwrap-panic (slice? bytes u15 u16)))
                    (b2 (unwrap-panic (slice? bytes u14 u15)))
                )
                (if (< n u128)
                    b0
                    (if (< n u256)
                        (concat b0 0x00)
                        (if (< n u32768)
                            (concat b0 b1)
                            (if (< n u65536)
                                (concat b0 (concat b1 0x00))
                                (concat b0 (concat b1 b2))
                            )
                        )
                    )
                )
            )
        )
        u5
    ))
)

(define-read-only (push-c-script-num (n uint))
    (if (is-eq n u0)
        0x00
        (if (<= n u16)
            (unwrap-panic (as-max-len?
                (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? (+ u80 n))) u16 u17))
                u1
            ))
            (push-script-bytes (serialize-c-script-num n))
        )
    )
)
