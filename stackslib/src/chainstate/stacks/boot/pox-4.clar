;; The .pox-4 contract
;; Error codes
(define-constant ERR_STACKING_UNREACHABLE 255)
(define-constant ERR_STACKING_CORRUPTED_STATE 254)
(define-constant ERR_STACKING_INSUFFICIENT_FUNDS 1)
(define-constant ERR_STACKING_INVALID_LOCK_PERIOD 2)
(define-constant ERR_STACKING_ALREADY_STACKED 3)
(define-constant ERR_STACKING_NO_SUCH_PRINCIPAL 4)
(define-constant ERR_STACKING_EXPIRED 5)
(define-constant ERR_STACKING_STX_LOCKED 6)
(define-constant ERR_STACKING_PERMISSION_DENIED 9)
(define-constant ERR_STACKING_THRESHOLD_NOT_MET 11)
(define-constant ERR_STACKING_POX_ADDRESS_IN_USE 12)
(define-constant ERR_STACKING_INVALID_POX_ADDRESS 13)

(define-constant ERR_STACKING_INVALID_AMOUNT 18)
(define-constant ERR_NOT_ALLOWED 19)
(define-constant ERR_STACKING_ALREADY_DELEGATED 20)
(define-constant ERR_DELEGATION_EXPIRES_DURING_LOCK 21)
(define-constant ERR_DELEGATION_TOO_MUCH_LOCKED 22)
(define-constant ERR_DELEGATION_POX_ADDR_REQUIRED 23)
(define-constant ERR_INVALID_START_BURN_HEIGHT 24)
(define-constant ERR_NOT_CURRENT_STACKER 25)
(define-constant ERR_STACK_EXTEND_NOT_LOCKED 26)
(define-constant ERR_STACK_INCREASE_NOT_LOCKED 27)
(define-constant ERR_DELEGATION_NO_REWARD_SLOT 28)
(define-constant ERR_DELEGATION_WRONG_REWARD_SLOT 29)
(define-constant ERR_STACKING_IS_DELEGATED 30)
(define-constant ERR_STACKING_NOT_DELEGATED 31)
(define-constant ERR_INVALID_SIGNER_KEY 32)
(define-constant ERR_REUSED_SIGNER_KEY 33)
(define-constant ERR_DELEGATION_ALREADY_REVOKED 34)
(define-constant ERR_INVALID_SIGNATURE_PUBKEY 35)
(define-constant ERR_INVALID_SIGNATURE_RECOVER 36)
(define-constant ERR_INVALID_REWARD_CYCLE 37)
(define-constant ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH 38)
(define-constant ERR_SIGNER_AUTH_USED 39)
(define-constant ERR_INVALID_INCREASE 40)

;; Valid values for burnchain address versions.
;; These first four correspond to address hash modes in Stacks 2.1,
;; and are defined in pox-mainnet.clar and pox-testnet.clar (so they
;; cannot be defined here again).
(define-constant ADDRESS_VERSION_P2PKH 0x00)
(define-constant ADDRESS_VERSION_P2SH 0x01)
(define-constant ADDRESS_VERSION_P2WPKH 0x02)
(define-constant ADDRESS_VERSION_P2WSH 0x03)
(define-constant ADDRESS_VERSION_NATIVE_P2WPKH 0x04)
(define-constant ADDRESS_VERSION_NATIVE_P2WSH 0x05)
(define-constant ADDRESS_VERSION_NATIVE_P2TR 0x06)

;; Values for stacks address versions
(define-constant STACKS_ADDR_VERSION_MAINNET 0x16)
(define-constant STACKS_ADDR_VERSION_TESTNET 0x1a)

;; Keep these constants in lock-step with the address version buffs above
;; Maximum value of an address version as a uint
(define-constant MAX_ADDRESS_VERSION u6)
;; Maximum value of an address version that has a 20-byte hashbytes
;; (0x00, 0x01, 0x02, 0x03, and 0x04 have 20-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_20 u4)
;; Maximum value of an address version that has a 32-byte hashbytes
;; (0x05 and 0x06 have 32-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_32 u6)

;; PoX mainnet constants
;; Min/max number of reward cycles uSTX can be locked for
(define-constant MIN_POX_REWARD_CYCLES u1)
(define-constant MAX_POX_REWARD_CYCLES u12)

;; Default length of the PoX registration window, in burnchain blocks.
(define-constant PREPARE_CYCLE_LENGTH (if is-in-mainnet u100 u50))

;; Default length of the PoX reward cycle, in burnchain blocks.
(define-constant REWARD_CYCLE_LENGTH (if is-in-mainnet u2100 u1050))

;; Stacking thresholds
(define-constant STACKING_THRESHOLD_25 (if is-in-mainnet u20000 u8000))

;; SIP18 message prefix
(define-constant SIP018_MSG_PREFIX 0x534950303138)

;; Data vars that store a copy of the burnchain configuration.
;; Implemented as data-vars, so that different configurations can be
;; used in e.g. test harnesses.
(define-data-var pox-prepare-cycle-length uint PREPARE_CYCLE_LENGTH)
(define-data-var pox-reward-cycle-length uint REWARD_CYCLE_LENGTH)
(define-data-var first-burnchain-block-height uint u0)
(define-data-var configured bool false)
(define-data-var first-pox-4-reward-cycle uint u0)

;; This function can only be called once, when it boots up
(define-public (set-burnchain-parameters (first-burn-height uint)
                                         (prepare-cycle-length uint)
                                         (reward-cycle-length uint)
                                         (begin-pox-4-reward-cycle uint))
    (begin
        (asserts! (not (var-get configured)) (err ERR_NOT_ALLOWED))
        (var-set first-burnchain-block-height first-burn-height)
        (var-set pox-prepare-cycle-length prepare-cycle-length)
        (var-set pox-reward-cycle-length reward-cycle-length)
        (var-set first-pox-4-reward-cycle begin-pox-4-reward-cycle)
        (var-set configured true)
        (ok true))
)

;; The Stacking lock-up state and associated metadata.
;; Records are inserted into this map via `stack-stx`, `delegate-stack-stx`, `stack-extend`
;;  `delegate-stack-extend` and burnchain transactions for invoking `stack-stx`, etc.
;; Records will be deleted from this map when auto-unlocks are processed
;;
;; This map de-normalizes some state from the `reward-cycle-pox-address-list` map
;;  and the `pox-4` contract tries to keep this state in sync with the reward-cycle
;;  state. The major invariants of this `stacking-state` map are:
;;    (1) any entry in `reward-cycle-pox-address-list` with `some stacker` points to a real `stacking-state`
;;    (2) `stacking-state.reward-set-indexes` matches the index of that `reward-cycle-pox-address-list`
;;    (3) all `stacking-state.reward-set-indexes` match the index of their reward cycle entries
;;    (4) `stacking-state.pox-addr` matches `reward-cycle-pox-address-list.pox-addr`
;;    (5) if set, (len reward-set-indexes) == lock-period
;;    (6) (reward-cycle-to-burn-height (+ lock-period first-reward-cycle)) == (get unlock-height (stx-account stacker))
;;  These invariants only hold while `cur-reward-cycle < (+ lock-period first-reward-cycle)`
;;
(define-map stacking-state
    { stacker: principal }
    {
        ;; Description of the underlying burnchain address that will
        ;; receive PoX'ed tokens. Translating this into an address
        ;; depends on the burnchain being used.  When Bitcoin is
        ;; the burnchain, this gets translated into a p2pkh, p2sh,
        ;; p2wpkh-p2sh, p2wsh-p2sh, p2wpkh, p2wsh, or p2tr UTXO,
        ;; depending on the version.  The `hashbytes` field *must* be
        ;; either 20 bytes or 32 bytes, depending on the output.
        pox-addr: { version: (buff 1), hashbytes: (buff 32) },
        ;; how long the uSTX are locked, in reward cycles.
        lock-period: uint,
        ;; reward cycle when rewards begin
        first-reward-cycle: uint,
        ;; indexes in each reward-set associated with this user.
        ;; these indexes are only valid looking forward from
        ;;  `first-reward-cycle` (i.e., they do not correspond
        ;;  to entries in the reward set that may have been from
        ;;  previous stack-stx calls, or prior to an extend)
        reward-set-indexes: (list 12 uint),
        ;; principal of the delegate, if stacker has delegated
        delegated-to: (optional principal),
    }
)

;; Delegation relationships
(define-map delegation-state
    { stacker: principal }
    {
        amount-ustx: uint,              ;; how many uSTX delegated?
        delegated-to: principal,        ;; who are we delegating?
        until-burn-ht: (optional uint), ;; how long does the delegation last?
        ;; does the delegate _need_ to use a specific
        ;; pox recipient address?
        pox-addr: (optional { version: (buff 1), hashbytes: (buff 32) })
    }
)

;; allowed contract-callers
(define-map allowance-contract-callers
    { sender: principal, contract-caller: principal }
    { until-burn-ht: (optional uint) })

;; How many uSTX are stacked in a given reward cycle.
;; Updated when a new PoX address is registered, or when more STX are granted
;; to it.
(define-map reward-cycle-total-stacked
    { reward-cycle: uint }
    { total-ustx: uint }
)

;; Internal map read by the Stacks node to iterate through the list of
;; PoX reward addresses on a per-reward-cycle basis.
(define-map reward-cycle-pox-address-list
    { reward-cycle: uint, index: uint }
    {
        pox-addr: { version: (buff 1), hashbytes: (buff 32) },
        total-ustx: uint,
        stacker: (optional principal),
        signer: (buff 33)
    }
)

(define-map reward-cycle-pox-address-list-len
    { reward-cycle: uint }
    { len: uint }
)

;; how much has been locked up for this address before
;;   committing?
;; this map allows stackers to stack amounts < minimum
;;   by paying the cost of aggregation during the commit
(define-map partial-stacked-by-cycle
    {
        pox-addr: { version: (buff 1), hashbytes: (buff 32) },
        reward-cycle: uint,
        sender: principal
    }
    { stacked-amount: uint }
)

;; This is identical to partial-stacked-by-cycle, but its data is never deleted.
;; It is used to preserve data for downstream clients to observe aggregate
;; commits.  Each key/value pair in this map is simply the last value of
;; partial-stacked-by-cycle right after it was deleted (so, subsequent calls
;; to the `stack-aggregation-*` functions will overwrite this).
(define-map logged-partial-stacked-by-cycle
    {
        pox-addr: { version: (buff 1), hashbytes: (buff 32) },
        reward-cycle: uint,
        sender: principal
    }
    { stacked-amount: uint }
)

;; State for setting authorizations for signer keys to be used in
;; certain stacking transactions. These fields match the fields used
;; in the message hash for signature-based signer key authorizations.
;; Values in this map are set in `set-signer-key-authorization`.
(define-map signer-key-authorizations
    {
        ;; The signer key being authorized
        signer-key: (buff 33),
        ;; The reward cycle for which the authorization is valid.
        ;; For `stack-stx` and `stack-extend`, this refers to the reward
        ;; cycle where the transaction is confirmed. For `stack-aggregation-commit`,
        ;; this refers to the reward cycle argument in that function.
        reward-cycle: uint,
        ;; For `stack-stx`, this refers to `lock-period`. For `stack-extend`,
        ;; this refers to `extend-count`. For `stack-aggregation-commit`, this is `u1`.
        period: uint,
        ;; A string representing the function where this authorization is valid. Either
        ;; `stack-stx`, `stack-extend`, `stack-increase` or `agg-commit`.
        topic: (string-ascii 14),
        ;; The PoX address that can be used with this signer key
        pox-addr: { version: (buff 1), hashbytes: (buff 32) },
        ;; The unique auth-id for this authorization
        auth-id: uint,
        ;; The maximum amount of uSTX that can be used (per tx) with this signer key
        max-amount: uint,
    }
    bool ;; Whether the authorization can be used or not
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
        pox-addr: { version: (buff 1), hashbytes: (buff 32) },
        auth-id: uint,
        max-amount: uint,
    }
    bool ;; Whether the field has been used or not
)

;; What's the reward cycle number of the burnchain block height?
;; Will runtime-abort if height is less than the first burnchain block (this is intentional)
(define-read-only (burn-height-to-reward-cycle (height uint))
    (/ (- height (var-get first-burnchain-block-height)) (var-get pox-reward-cycle-length)))

;; What's the block height at the start of a given reward cycle?
(define-read-only (reward-cycle-to-burn-height (cycle uint))
    (+ (var-get first-burnchain-block-height) (* cycle (var-get pox-reward-cycle-length))))

;; What's the current PoX reward cycle?
(define-read-only (current-pox-reward-cycle)
    (burn-height-to-reward-cycle burn-block-height))

;; Get the _current_ PoX stacking principal information.  If the information
;; is expired, or if there's never been such a stacker, then returns none.
(define-read-only (get-stacker-info (stacker principal))
    (match (map-get? stacking-state { stacker: stacker })
        stacking-info
            (if (<= (+ (get first-reward-cycle stacking-info) (get lock-period stacking-info)) (current-pox-reward-cycle))
                ;; present, but lock has expired
                none
                ;; present, and lock has not expired
                (some stacking-info)
            )
        ;; no state at all
        none
    ))

(define-read-only (check-caller-allowed)
    (or (is-eq tx-sender contract-caller)
        (let ((caller-allowed
                 ;; if not in the caller map, return false
                 (unwrap! (map-get? allowance-contract-callers
                                    { sender: tx-sender, contract-caller: contract-caller })
                          false))
               (expires-at
                 ;; if until-burn-ht not set, then return true (because no expiry)
                 (unwrap! (get until-burn-ht caller-allowed) true)))
          ;; is the caller allowance expired?
          (if (>= burn-block-height expires-at)
              false
              true))))

(define-read-only (get-check-delegation (stacker principal))
    (let ((delegation-info (try! (map-get? delegation-state { stacker: stacker }))))
      ;; did the existing delegation expire?
      (if (match (get until-burn-ht delegation-info)
                 until-burn-ht (> burn-block-height until-burn-ht)
                 false)
          ;; it expired, return none
          none
          ;; delegation is active
          (some delegation-info))))

;; Get the size of the reward set for a reward cycle.
;; Note that this also _will_ return PoX addresses that are beneath
;; the minimum threshold -- i.e. the threshold can increase after insertion.
;; Used internally by the Stacks node, which filters out the entries
;; in this map to select PoX addresses with enough STX.
(define-read-only (get-reward-set-size (reward-cycle uint))
    (default-to
        u0
        (get len (map-get? reward-cycle-pox-address-list-len { reward-cycle: reward-cycle }))))

;; Add a single PoX address to a single reward cycle.
;; Used to build up a set of per-reward-cycle PoX addresses.
;; No checking will be done -- don't call if this PoX address is already registered in this reward cycle!
;; Returns the index into the reward cycle that the PoX address is stored to
(define-private (append-reward-cycle-pox-addr (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
                                              (reward-cycle uint)
                                              (amount-ustx uint)
                                              (stacker (optional principal))
                                              (signer (buff 33)))
    (let ((sz (get-reward-set-size reward-cycle)))
        (map-set reward-cycle-pox-address-list
            { reward-cycle: reward-cycle, index: sz }
            { pox-addr: pox-addr, total-ustx: amount-ustx, stacker: stacker, signer: signer })
        (map-set reward-cycle-pox-address-list-len
            { reward-cycle: reward-cycle }
            { len: (+ u1 sz) })
    sz))

;; How many uSTX are stacked?
(define-read-only (get-total-ustx-stacked (reward-cycle uint))
    (default-to
        u0
        (get total-ustx (map-get? reward-cycle-total-stacked { reward-cycle: reward-cycle })))
)

;; Called internally by the node to iterate through the list of PoX addresses in this reward cycle.
;; Returns (optional (tuple (pox-addr <pox-address>) (total-ustx <uint>)))
(define-read-only (get-reward-set-pox-address (reward-cycle uint) (index uint))
    (map-get? reward-cycle-pox-address-list { reward-cycle: reward-cycle, index: index }))

;; Add a PoX address to the `cycle-index`-th reward cycle, if `cycle-index` is between 0 and the given num-cycles (exclusive).
;; Arguments are given as a tuple, so this function can be (folded ..)'ed onto a list of its arguments.
;; Used by add-pox-addr-to-reward-cycles.
;; No checking is done.
;; The returned tuple is the same as inputted `params`, but the `i` field is incremented if
;;  the pox-addr was added to the given cycle.  Also, `reward-set-indexes` grows to include all
;;  of the `reward-cycle-index` key parts of the `reward-cycle-pox-address-list` which get added by this function.
;;  This way, the caller knows which items in a given reward cycle's PoX address list got updated.
(define-private (add-pox-addr-to-ith-reward-cycle (cycle-index uint) (params (tuple
                                                            (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
                                                            (reward-set-indexes (list 12 uint))
                                                            (first-reward-cycle uint)
                                                            (num-cycles uint)
                                                            (stacker (optional principal))
                                                            (signer (buff 33))
                                                            (amount-ustx uint)
                                                            (i uint))))
    (let ((reward-cycle (+ (get first-reward-cycle params) (get i params)))
          (num-cycles (get num-cycles params))
          (i (get i params))
          (reward-set-index (if (< i num-cycles)
            (let ((total-ustx (get-total-ustx-stacked reward-cycle))
                  (reward-index
                      ;; record how many uSTX this pox-addr will stack for in the given reward cycle
                      (append-reward-cycle-pox-addr
                        (get pox-addr params)
                        reward-cycle
                        (get amount-ustx params)
                        (get stacker params)
                        (get signer params)
                        )))
                  ;; update running total
                  (map-set reward-cycle-total-stacked
                     { reward-cycle: reward-cycle }
                     { total-ustx: (+ (get amount-ustx params) total-ustx) })
                  (some reward-index))
            none))
          (next-i (if (< i num-cycles) (+ i u1) i)))
    {
        pox-addr: (get pox-addr params),
        first-reward-cycle: (get first-reward-cycle params),
        num-cycles: num-cycles,
        amount-ustx: (get amount-ustx params),
        stacker: (get stacker params),
        signer: (get signer params),
        reward-set-indexes: (match
            reward-set-index new (unwrap-panic (as-max-len? (append (get reward-set-indexes params) new) u12))
            (get reward-set-indexes params)),
        i: next-i
    }))

;; Add a PoX address to a given sequence of reward cycle lists.
;; A PoX address can be added to at most 12 consecutive cycles.
;; No checking is done.
(define-private (add-pox-addr-to-reward-cycles (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
                                               (first-reward-cycle uint)
                                               (num-cycles uint)
                                               (amount-ustx uint)
                                               (stacker principal)
                                               (signer (buff 33)))
  (let ((cycle-indexes (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11))
        (results (fold add-pox-addr-to-ith-reward-cycle cycle-indexes
                         { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles,
                           reward-set-indexes: (list), amount-ustx: amount-ustx, i: u0, stacker: (some stacker), signer: signer }))
        (reward-set-indexes (get reward-set-indexes results)))
    ;; For safety, add up the number of times (add-principal-to-ith-reward-cycle) returns 1.
    ;; It _should_ be equal to num-cycles.
    (asserts! (is-eq num-cycles (get i results)) (err ERR_STACKING_UNREACHABLE))
    (asserts! (is-eq num-cycles (len reward-set-indexes)) (err ERR_STACKING_UNREACHABLE))
    (ok reward-set-indexes)))

(define-private (add-pox-partial-stacked-to-ith-cycle
                 (cycle-index uint)
                 (params { pox-addr: { version: (buff 1), hashbytes: (buff 32) },
                           reward-cycle: uint,
                           num-cycles: uint,
                           amount-ustx: uint }))
  (let ((pox-addr     (get pox-addr     params))
        (num-cycles   (get num-cycles   params))
        (reward-cycle (get reward-cycle params))
        (amount-ustx  (get amount-ustx  params)))
    (let ((current-amount
           (default-to u0
             (get stacked-amount
                  (map-get? partial-stacked-by-cycle { sender: tx-sender, pox-addr: pox-addr, reward-cycle: reward-cycle })))))
      (if (>= cycle-index num-cycles)
          ;; do not add to cycles >= cycle-index
          false
          ;; otherwise, add to the partial-stacked-by-cycle
          (map-set partial-stacked-by-cycle
                   { sender: tx-sender, pox-addr: pox-addr, reward-cycle: reward-cycle }
                   { stacked-amount: (+ amount-ustx current-amount) }))
      ;; produce the next params tuple
      { pox-addr: pox-addr,
        reward-cycle: (+ u1 reward-cycle),
        num-cycles: num-cycles,
        amount-ustx: amount-ustx })))

;; Add a PoX address to a given sequence of partial reward cycle lists.
;; A PoX address can be added to at most 12 consecutive cycles.
;; No checking is done.
(define-private (add-pox-partial-stacked (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
                                         (first-reward-cycle uint)
                                         (num-cycles uint)
                                         (amount-ustx uint))
  (let ((cycle-indexes (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11)))
    (fold add-pox-partial-stacked-to-ith-cycle cycle-indexes
          { pox-addr: pox-addr, reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx })
    true))

;; What is the minimum number of uSTX to be stacked in the given reward cycle?
;; Used internally by the Stacks node, and visible publicly.
(define-read-only (get-stacking-minimum)
    (/ stx-liquid-supply STACKING_THRESHOLD_25))

;; Is the address mode valid for a PoX address?
(define-read-only (check-pox-addr-version (version (buff 1)))
    (<= (buff-to-uint-be version) MAX_ADDRESS_VERSION))

;; Is this buffer the right length for the given PoX address?
(define-read-only (check-pox-addr-hashbytes (version (buff 1)) (hashbytes (buff 32)))
    (if (<= (buff-to-uint-be version) MAX_ADDRESS_VERSION_BUFF_20)
        (is-eq (len hashbytes) u20)
        (if (<= (buff-to-uint-be version) MAX_ADDRESS_VERSION_BUFF_32)
            (is-eq (len hashbytes) u32)
            false)))

;; Is the given lock period valid?
(define-read-only (check-pox-lock-period (lock-period uint))
    (and (>= lock-period MIN_POX_REWARD_CYCLES)
         (<= lock-period MAX_POX_REWARD_CYCLES)))

;; Evaluate if a participant can stack an amount of STX for a given period.
;; This method is designed as a read-only method so that it can be used as
;; a set of guard conditions and also as a read-only RPC call that can be
;; performed beforehand.
(define-read-only (can-stack-stx (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
                                  (amount-ustx uint)
                                  (first-reward-cycle uint)
                                  (num-cycles uint))
  (begin
    ;; minimum uSTX must be met
    (asserts! (<= (get-stacking-minimum) amount-ustx)
              (err ERR_STACKING_THRESHOLD_NOT_MET))

    (minimal-can-stack-stx pox-addr amount-ustx first-reward-cycle num-cycles)))

;; Evaluate if a participant can stack an amount of STX for a given period.
;; This method is designed as a read-only method so that it can be used as
;; a set of guard conditions and also as a read-only RPC call that can be
;; performed beforehand.
(define-read-only (minimal-can-stack-stx
                   (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
                   (amount-ustx uint)
                   (first-reward-cycle uint)
                   (num-cycles uint))
  (begin
    ;; amount must be valid
    (asserts! (> amount-ustx u0)
              (err ERR_STACKING_INVALID_AMOUNT))

    ;; lock period must be in acceptable range.
    (asserts! (check-pox-lock-period num-cycles)
              (err ERR_STACKING_INVALID_LOCK_PERIOD))

    ;; address version must be valid
    (asserts! (check-pox-addr-version (get version pox-addr))
              (err ERR_STACKING_INVALID_POX_ADDRESS))

    ;; address hashbytes must be valid for the version
    (asserts! (check-pox-addr-hashbytes (get version pox-addr) (get hashbytes pox-addr))
              (err ERR_STACKING_INVALID_POX_ADDRESS))

    (ok true)))

;; Revoke contract-caller authorization to call stacking methods
(define-public (disallow-contract-caller (caller principal))
  (begin
    (asserts! (is-eq tx-sender contract-caller)
              (err ERR_STACKING_PERMISSION_DENIED))
    (ok (map-delete allowance-contract-callers { sender: tx-sender, contract-caller: caller }))))

;; Give a contract-caller authorization to call stacking methods
;;  normally, stacking methods may only be invoked by _direct_ transactions
;;   (i.e., the tx-sender issues a direct contract-call to the stacking methods)
;;  by issuing an allowance, the tx-sender may call through the allowed contract
(define-public (allow-contract-caller (caller principal) (until-burn-ht (optional uint)))
  (begin
    (asserts! (is-eq tx-sender contract-caller)
              (err ERR_STACKING_PERMISSION_DENIED))
    (ok (map-set allowance-contract-callers
               { sender: tx-sender, contract-caller: caller }
               { until-burn-ht: until-burn-ht }))))

;; Lock up some uSTX for stacking!  Note that the given amount here is in micro-STX (uSTX).
;; The STX will be locked for the given number of reward cycles (lock-period).
;; This is the self-service interface.  tx-sender will be the Stacker.
;;
;; * The given stacker cannot currently be stacking.
;; * You will need the minimum uSTX threshold.  This will be determined by (get-stacking-minimum)
;; at the time this method is called.
;; * You may need to increase the amount of uSTX locked up later, since the minimum uSTX threshold
;; may increase between reward cycles.
;; * You need to provide a signer key to be used in the signer DKG process.
;; * The Stacker will receive rewards in the reward cycle following `start-burn-ht`.
;; Importantly, `start-burn-ht` may not be further into the future than the next reward cycle,
;; and in most cases should be set to the current burn block height.
;; 
;; To ensure that the Stacker is authorized to use the provided `signer-key`, the stacker
;; must provide either a signature have an authorization already saved. Refer to
;; `verify-signer-key-sig` for more information.
;;
;; The tokens will unlock and be returned to the Stacker (tx-sender) automatically.
(define-public (stack-stx (amount-ustx uint)
                          (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
                          (start-burn-ht uint)
                          (lock-period uint)
                          (signer-sig (optional (buff 65)))
                          (signer-key (buff 33))
                          (max-amount uint)
                          (auth-id uint))
    ;; this stacker's first reward cycle is the _next_ reward cycle
    (let ((first-reward-cycle (+ u1 (current-pox-reward-cycle)))
          (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht))))
      ;; the start-burn-ht must result in the next reward cycle, do not allow stackers
      ;;  to "post-date" their `stack-stx` transaction
      (asserts! (is-eq first-reward-cycle specified-reward-cycle)
                (err ERR_INVALID_START_BURN_HEIGHT))

      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
                (err ERR_STACKING_PERMISSION_DENIED))

      ;; tx-sender principal must not be stacking
      (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR_STACKING_ALREADY_STACKED))

      ;; tx-sender must not be delegating
      (asserts! (is-none (get-check-delegation tx-sender))
        (err ERR_STACKING_ALREADY_DELEGATED))

      ;; the Stacker must have sufficient unlocked funds
      (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
        (err ERR_STACKING_INSUFFICIENT_FUNDS))

      ;; Validate ownership of the given signer key
      (try! (consume-signer-key-authorization pox-addr (- first-reward-cycle u1) "stack-stx" lock-period signer-sig signer-key amount-ustx max-amount auth-id))

      ;; ensure that stacking can be performed
      (try! (can-stack-stx pox-addr amount-ustx first-reward-cycle lock-period))

      ;; register the PoX address with the amount stacked
      (let ((reward-set-indexes (try! (add-pox-addr-to-reward-cycles pox-addr first-reward-cycle lock-period amount-ustx tx-sender signer-key))))
          ;; add stacker record
         (map-set stacking-state
           { stacker: tx-sender }
           { pox-addr: pox-addr,
             reward-set-indexes: reward-set-indexes,
             first-reward-cycle: first-reward-cycle,
             lock-period: lock-period,
             delegated-to: none })

          ;; return the lock-up information, so the node can actually carry out the lock.
          (ok { stacker: tx-sender, lock-amount: amount-ustx, signer-key: signer-key, unlock-burn-height: (reward-cycle-to-burn-height (+ first-reward-cycle lock-period)) }))))

;; Revokes the delegation to the current stacking pool.
;; New in pox-4: Fails if the delegation was already revoked.
;; Returns the last delegation state.
(define-public (revoke-delegate-stx)
  (let ((last-delegation-state (get-check-delegation tx-sender)))
    ;; must be called directly by the tx-sender or by an allowed contract-caller
    (asserts! (check-caller-allowed)
              (err ERR_STACKING_PERMISSION_DENIED))
    (asserts! (is-some last-delegation-state) (err ERR_DELEGATION_ALREADY_REVOKED))
    (asserts! (map-delete delegation-state { stacker: tx-sender }) (err ERR_DELEGATION_ALREADY_REVOKED))
    (ok last-delegation-state)))

;; Delegate to `delegate-to` the ability to stack from a given address.
;;  This method _does not_ lock the funds, rather, it allows the delegate
;;  to issue the stacking lock.
;; The caller specifies:
;;   * amount-ustx: the total amount of ustx the delegate may be allowed to lock
;;   * until-burn-ht: an optional burn height at which this delegation expires
;;   * pox-addr: an optional address to which any rewards *must* be sent
(define-public (delegate-stx (amount-ustx uint)
                             (delegate-to principal)
                             (until-burn-ht (optional uint))
                             (pox-addr (optional { version: (buff 1), hashbytes: (buff 32) })))

    (begin
      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
                (err ERR_STACKING_PERMISSION_DENIED))

      ;; delegate-stx no longer requires the delegator to not currently
      ;; be stacking.
      ;; delegate-stack-* functions assert that
      ;; 1. users can't swim in two pools at the same time.
      ;; 2. users can't switch pools without cool down cycle.
      ;;    Other pool admins can't increase or extend.
      ;; 3. users can't join a pool while already directly stacking.

      ;; pox-addr, if given, must be valid
      (match pox-addr
         address
            (asserts! (check-pox-addr-version (get version address))
                (err ERR_STACKING_INVALID_POX_ADDRESS))
         true)

      (match pox-addr
         pox-tuple
            (asserts! (check-pox-addr-hashbytes (get version pox-tuple) (get hashbytes pox-tuple))
                (err ERR_STACKING_INVALID_POX_ADDRESS))
         true)

      ;; tx-sender must not be delegating
      (asserts! (is-none (get-check-delegation tx-sender))
        (err ERR_STACKING_ALREADY_DELEGATED))

      ;; add delegation record
      (map-set delegation-state
        { stacker: tx-sender }
        { amount-ustx: amount-ustx,
          delegated-to: delegate-to,
          until-burn-ht: until-burn-ht,
          pox-addr: pox-addr })

      (ok true)))

;; Generate a message hash for validating a signer key.
;; The message hash follows SIP018 for signing structured data. The structured data
;; is the tuple `{ pox-addr: { version, hashbytes }, reward-cycle, auth-id, max-amount }`.
;; The domain is `{ name: "pox-4-signer", version: "1.0.0", chain-id: chain-id }`.
(define-read-only (get-signer-key-message-hash (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                               (reward-cycle uint)
                                               (topic (string-ascii 14))
                                               (period uint)
                                               (max-amount uint)
                                               (auth-id uint))
  (sha256 (concat
    SIP018_MSG_PREFIX
    (concat
      (sha256 (unwrap-panic (to-consensus-buff? { name: "pox-4-signer", version: "1.0.0", chain-id: chain-id })))
      (sha256 (unwrap-panic
        (to-consensus-buff? {
          pox-addr: pox-addr,
          reward-cycle: reward-cycle,
          topic: topic,
          period: period,
          auth-id: auth-id,
          max-amount: max-amount,
        })))))))

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
(define-read-only (verify-signer-key-sig (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                         (reward-cycle uint)
                                         (topic (string-ascii 14))
                                         (period uint)
                                         (signer-sig-opt (optional (buff 65)))
                                         (signer-key (buff 33))
                                         (amount uint)
                                         (max-amount uint)
                                         (auth-id uint))
  (begin
    ;; Validate that amount is less than or equal to `max-amount`
    (asserts! (>= max-amount amount) (err ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH))
    (asserts! (is-none (map-get? used-signer-key-authorizations { signer-key: signer-key, reward-cycle: reward-cycle, topic: topic, period: period, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount }))
              (err ERR_SIGNER_AUTH_USED))
    (match signer-sig-opt
      ;; `signer-sig` is present, verify the signature
      signer-sig (ok (asserts!
        (is-eq
          (unwrap! (secp256k1-recover?
            (get-signer-key-message-hash pox-addr reward-cycle topic period max-amount auth-id)
            signer-sig) (err ERR_INVALID_SIGNATURE_RECOVER))
          signer-key)
        (err ERR_INVALID_SIGNATURE_PUBKEY)))
      ;; `signer-sig` is not present, verify that an authorization was previously added for this key
      (ok (asserts! (default-to false (map-get? signer-key-authorizations
            { signer-key: signer-key, reward-cycle: reward-cycle, period: period, topic: topic, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount }))
          (err ERR_NOT_ALLOWED)))
    ))
  )

;; This function does two things:
;;
;; - Verify that a signer key is authorized to be used
;; - Updates the `used-signer-key-authorizations` map to prevent reuse
;;
;; This "wrapper" method around `verify-signer-key-sig` allows that function to remain
;; read-only, so that it can be used by clients as a sanity check before submitting a transaction.
(define-private (consume-signer-key-authorization (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                                  (reward-cycle uint)
                                                  (topic (string-ascii 14))
                                                  (period uint)
                                                  (signer-sig-opt (optional (buff 65)))
                                                  (signer-key (buff 33))
                                                  (amount uint)
                                                  (max-amount uint)
                                                  (auth-id uint))
  (begin
    ;; verify the authorization
    (try! (verify-signer-key-sig pox-addr reward-cycle topic period signer-sig-opt signer-key amount max-amount auth-id))
    ;; update the `used-signer-key-authorizations` map
    (asserts! (map-insert used-signer-key-authorizations
      { signer-key: signer-key, reward-cycle: reward-cycle, topic: topic, period: period, pox-addr: pox-addr, auth-id: auth-id, max-amount: max-amount } true)
      (err ERR_SIGNER_AUTH_USED))
    (ok true)))

;; Commit partially stacked STX and allocate a new PoX reward address slot.
;;   This allows a stacker/delegate to lock fewer STX than the minimal threshold in multiple transactions,
;;   so long as: 1. The pox-addr is the same.
;;               2. This "commit" transaction is called _before_ the PoX anchor block.
;;   This ensures that each entry in the reward set returned to the stacks-node is greater than the threshold,
;;   but does not require it be all locked up within a single transaction
;;
;; Returns (ok uint) on success, where the given uint is the reward address's index in the list of reward
;; addresses allocated in this reward cycle.  This index can then be passed to `stack-aggregation-increase`
;; to later increment the STX this PoX address represents, in amounts less than the stacking minimum.
;;
;; *New in Stacks 2.1.*
(define-private (inner-stack-aggregation-commit (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                                (reward-cycle uint)
                                                (signer-sig (optional (buff 65)))
                                                (signer-key (buff 33))
                                                (max-amount uint)
                                                (auth-id uint))
  (let ((partial-stacked
         ;; fetch the partial commitments
         (unwrap! (map-get? partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle })
                  (err ERR_STACKING_NO_SUCH_PRINCIPAL))))
    ;; must be called directly by the tx-sender or by an allowed contract-caller
    (asserts! (check-caller-allowed)
              (err ERR_STACKING_PERMISSION_DENIED))
    (let ((amount-ustx (get stacked-amount partial-stacked)))
      (try! (consume-signer-key-authorization pox-addr reward-cycle "agg-commit" u1 signer-sig signer-key amount-ustx max-amount auth-id))
      (try! (can-stack-stx pox-addr amount-ustx reward-cycle u1))
      ;; Add the pox addr to the reward cycle, and extract the index of the PoX address
      ;; so the delegator can later use it to call stack-aggregation-increase.
      (let ((add-pox-addr-info
                (add-pox-addr-to-ith-reward-cycle
                   u0
                   { pox-addr: pox-addr,
                     first-reward-cycle: reward-cycle,
                     num-cycles: u1,
                     reward-set-indexes: (list),
                     stacker: none,
                     signer: signer-key,
                     amount-ustx: amount-ustx,
                     i: u0 }))
           (pox-addr-index (unwrap-panic
                (element-at (get reward-set-indexes add-pox-addr-info) u0))))

        ;; don't update the stacking-state map,
        ;;  because it _already has_ this stacker's state
        ;; don't lock the STX, because the STX is already locked
        ;;
        ;; clear the partial-stacked state, and log it
        (map-delete partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle })
        (map-set logged-partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle } partial-stacked)
        (ok pox-addr-index)))))

;; Legacy interface for stack-aggregation-commit.
;; Wraps inner-stack-aggregation-commit.  See its docstring for details.
;; Returns (ok true) on success
;; Returns (err ...) on failure.
(define-public (stack-aggregation-commit (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                         (reward-cycle uint)
                                         (signer-sig (optional (buff 65)))
                                         (signer-key (buff 33))
                                         (max-amount uint)
                                         (auth-id uint))
    (match (inner-stack-aggregation-commit pox-addr reward-cycle signer-sig signer-key max-amount auth-id)
        pox-addr-index (ok true)
        commit-err (err commit-err)))

;; Public interface to `inner-stack-aggregation-commit`.  See its documentation for details.
;; *New in Stacks 2.1.*
(define-public (stack-aggregation-commit-indexed (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                                 (reward-cycle uint)
                                                 (signer-sig (optional (buff 65)))
                                                 (signer-key (buff 33))
                                                 (max-amount uint)
                                                 (auth-id uint))
    (inner-stack-aggregation-commit pox-addr reward-cycle signer-sig signer-key max-amount auth-id))

;; Commit partially stacked STX to a PoX address which has already received some STX (more than the Stacking min).
;; This allows a delegator to lock up marginally more STX from new delegates, even if they collectively do not
;; exceed the Stacking minimum, so long as the target PoX address already represents at least as many STX as the
;; Stacking minimum.
;;
;; The `reward-cycle-index` is emitted as a contract event from `stack-aggregation-commit` when the initial STX are
;; locked up by this delegator.  It must be passed here to add more STX behind this PoX address.  If the delegator
;; called `stack-aggregation-commit` multiple times for the same PoX address, then any such `reward-cycle-index` will
;; work here.
;;
;; *New in Stacks 2.1*
;;
(define-public (stack-aggregation-increase (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                           (reward-cycle uint)
                                           (reward-cycle-index uint)
                                           (signer-sig (optional (buff 65)))
                                           (signer-key (buff 33))
                                           (max-amount uint)
                                           (auth-id uint))
  (let ((partial-stacked
         ;; fetch the partial commitments
         (unwrap! (map-get? partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle })
                  (err ERR_STACKING_NO_SUCH_PRINCIPAL))))

    ;; must be called directly by the tx-sender or by an allowed contract-caller
    (asserts! (check-caller-allowed)
              (err ERR_STACKING_PERMISSION_DENIED))

    ;; reward-cycle must be in the future
    (asserts! (> reward-cycle (current-pox-reward-cycle))
              (err ERR_STACKING_INVALID_LOCK_PERIOD))

    (let ((partial-amount-ustx (get stacked-amount partial-stacked))
          ;; reward-cycle and reward-cycle-index must point to an existing record in reward-cycle-pox-address-list
          (existing-entry (unwrap! (map-get? reward-cycle-pox-address-list { reward-cycle: reward-cycle, index: reward-cycle-index })
                          (err ERR_DELEGATION_NO_REWARD_SLOT)))
          ;; reward-cycle must point to an existing record in reward-cycle-total-stacked
          ;; infallible; getting existing-entry succeeded so this must succeed
          (existing-cycle (unwrap-panic (map-get? reward-cycle-total-stacked { reward-cycle: reward-cycle })))
          (increased-entry-total (+ (get total-ustx existing-entry) partial-amount-ustx))
          (increased-cycle-total (+ (get total-ustx existing-cycle) partial-amount-ustx))
          (existing-signer-key (get signer existing-entry)))

          ;; must be stackable
          (try! (minimal-can-stack-stx pox-addr increased-entry-total reward-cycle u1))

          ;; new total must exceed the stacking minimum
          (asserts! (<= (get-stacking-minimum) increased-entry-total)
                    (err ERR_STACKING_THRESHOLD_NOT_MET))

          ;; there must *not* be a stacker entry (since this is a delegator)
          (asserts! (is-none (get stacker existing-entry))
                    (err ERR_DELEGATION_WRONG_REWARD_SLOT))

          ;; the given PoX address must match the one on record
          (asserts! (is-eq pox-addr (get pox-addr existing-entry))
                    (err ERR_DELEGATION_WRONG_REWARD_SLOT))

          ;; Validate that amount is less than or equal to `max-amount`
          (asserts! (>= max-amount increased-entry-total) (err ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH))

          ;; Validate that signer-key matches the existing signer-key
          (asserts! (is-eq existing-signer-key signer-key) (err ERR_INVALID_SIGNER_KEY))

          ;; Verify signature from delegate that allows this sender for this cycle
          ;; 'lock-period' param set to one period, same as aggregation-commit-indexed
          (try! (consume-signer-key-authorization pox-addr reward-cycle "agg-increase" u1 signer-sig signer-key increased-entry-total max-amount auth-id))

          ;; update the pox-address list -- bump the total-ustx
          (map-set reward-cycle-pox-address-list
                   { reward-cycle: reward-cycle, index: reward-cycle-index }
                   { pox-addr: pox-addr,
                     total-ustx: increased-entry-total,
                     stacker: none,
                     signer: signer-key })

          ;; update the total ustx in this cycle
          (map-set reward-cycle-total-stacked
                   { reward-cycle: reward-cycle }
                   { total-ustx: increased-cycle-total })

          ;; don't update the stacking-state map,
          ;;  because it _already has_ this stacker's state
          ;; don't lock the STX, because the STX is already locked
          ;;
          ;; clear the partial-stacked state, and log it
          (map-delete partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle })
          (map-set logged-partial-stacked-by-cycle { pox-addr: pox-addr, sender: tx-sender, reward-cycle: reward-cycle } partial-stacked)
          (ok true))))

;; As a delegate, stack the given principal's STX using partial-stacked-by-cycle
;; Once the delegate has stacked > minimum, the delegate should call stack-aggregation-commit
(define-public (delegate-stack-stx (stacker principal)
                                   (amount-ustx uint)
                                   (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                                   (start-burn-ht uint)
                                   (lock-period uint))
    ;; this stacker's first reward cycle is the _next_ reward cycle
    (let ((first-reward-cycle (+ u1 (current-pox-reward-cycle)))
          (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht)))
          (unlock-burn-height (reward-cycle-to-burn-height (+ (current-pox-reward-cycle) u1 lock-period))))
      ;; the start-burn-ht must result in the next reward cycle, do not allow stackers
      ;;  to "post-date" their `stack-stx` transaction
      (asserts! (is-eq first-reward-cycle specified-reward-cycle)
                (err ERR_INVALID_START_BURN_HEIGHT))

      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
        (err ERR_STACKING_PERMISSION_DENIED))

      ;; stacker must have delegated to the caller
      (let ((delegation-info (unwrap! (get-check-delegation stacker) (err ERR_STACKING_PERMISSION_DENIED))))
        ;; must have delegated to tx-sender
        (asserts! (is-eq (get delegated-to delegation-info) tx-sender)
                  (err ERR_STACKING_PERMISSION_DENIED))
        ;; must have delegated enough stx
        (asserts! (>= (get amount-ustx delegation-info) amount-ustx)
                  (err ERR_DELEGATION_TOO_MUCH_LOCKED))
        ;; if pox-addr is set, must be equal to pox-addr
        (asserts! (match (get pox-addr delegation-info)
                         specified-pox-addr (is-eq pox-addr specified-pox-addr)
                         true)
                  (err ERR_DELEGATION_POX_ADDR_REQUIRED))
        ;; delegation must not expire before lock period
        (asserts! (match (get until-burn-ht delegation-info)
                         until-burn-ht (>= until-burn-ht
                                           unlock-burn-height)
                      true)
                  (err ERR_DELEGATION_EXPIRES_DURING_LOCK))
        )

      ;; stacker principal must not be stacking
      (asserts! (is-none (get-stacker-info stacker))
        (err ERR_STACKING_ALREADY_STACKED))

      ;; the Stacker must have sufficient unlocked funds
      (asserts! (>= (stx-get-balance stacker) amount-ustx)
        (err ERR_STACKING_INSUFFICIENT_FUNDS))

      ;; ensure that stacking can be performed
      (try! (minimal-can-stack-stx pox-addr amount-ustx first-reward-cycle lock-period))

      ;; register the PoX address with the amount stacked via partial stacking
      ;;   before it can be included in the reward set, this must be committed!
      (add-pox-partial-stacked pox-addr first-reward-cycle lock-period amount-ustx)

      ;; add stacker record
      (map-set stacking-state
        { stacker: stacker }
        { pox-addr: pox-addr,
          first-reward-cycle: first-reward-cycle,
          reward-set-indexes: (list),
          lock-period: lock-period,
          delegated-to: (some tx-sender) })

      ;; return the lock-up information, so the node can actually carry out the lock.
      (ok { stacker: stacker,
            lock-amount: amount-ustx,
            unlock-burn-height: unlock-burn-height })))


;; Used for PoX parameters discovery
(define-read-only (get-pox-info)
    (ok {
        min-amount-ustx: (get-stacking-minimum),
        reward-cycle-id: (current-pox-reward-cycle),
        prepare-cycle-length: (var-get pox-prepare-cycle-length),
        first-burnchain-block-height: (var-get first-burnchain-block-height),
        reward-cycle-length: (var-get pox-reward-cycle-length),
        total-liquid-supply-ustx: stx-liquid-supply,
    })
)

;; Update the number of stacked STX in a given reward cycle entry.
;; `reward-cycle-index` is the index into the `reward-cycle-pox-address-list` map for a given reward cycle number.
;; `updates`, if `(some ..)`, encodes which PoX reward cycle entry (if any) gets updated.  In particular, it must have
;; `(some stacker)` as the listed stacker, and must be an upcoming reward cycle.
(define-private (increase-reward-cycle-entry
                  (reward-cycle-index uint)
                  (updates (optional { first-cycle: uint, reward-cycle: uint, stacker: principal, add-amount: uint, signer-key: (buff 33) })))
    (let ((data (try! updates))
          (first-cycle (get first-cycle data))
          (reward-cycle (get reward-cycle data))
          (passed-signer-key (get signer-key data)))
    (if (> first-cycle reward-cycle)
        ;; not at first cycle to process yet
        (some { first-cycle: first-cycle, reward-cycle: (+ u1 reward-cycle), stacker: (get stacker data), add-amount: (get add-amount data), signer-key: (get signer-key data) })
        (let ((existing-entry (unwrap-panic (map-get? reward-cycle-pox-address-list { reward-cycle: reward-cycle, index: reward-cycle-index })))
              (existing-total (unwrap-panic (map-get? reward-cycle-total-stacked { reward-cycle: reward-cycle })))
              (existing-signer-key (get signer existing-entry))
              (add-amount (get add-amount data))
              (total-ustx (+ (get total-ustx existing-total) add-amount)))
            ;; stacker must match
            (asserts! (is-eq (get stacker existing-entry) (some (get stacker data))) none)
            ;; signer-key must match
            (asserts! (is-eq existing-signer-key passed-signer-key) none)
            ;; update the pox-address list
            (map-set reward-cycle-pox-address-list
                     { reward-cycle: reward-cycle, index: reward-cycle-index }
                     { pox-addr: (get pox-addr existing-entry),
                       ;; This addresses the bug in pox-2 (see SIP-022)
                       total-ustx: (+ (get total-ustx existing-entry) add-amount),
                       stacker: (some (get stacker data)),
                       signer: (get signer existing-entry) })
            ;; update the total
            (map-set reward-cycle-total-stacked
                     { reward-cycle: reward-cycle }
                     { total-ustx: total-ustx })
            (some { first-cycle: first-cycle,
                    reward-cycle: (+ u1 reward-cycle),
                    stacker: (get stacker data),
                    add-amount: (get add-amount data),
                    signer-key: passed-signer-key })))))

;; Increase the number of STX locked.
;; *New in Stacks 2.1*
;; This method locks up an additional amount of STX from `tx-sender`'s, indicated
;; by `increase-by`.  The `tx-sender` must already be Stacking & must not be
;; straddling more than one signer-key for the cycles effected. 
;; Refer to `verify-signer-key-sig` for more information on the authorization parameters
;; included here.
(define-public (stack-increase 
  (increase-by uint)
  (signer-sig (optional (buff 65)))
  (signer-key (buff 33))
  (max-amount uint)
  (auth-id uint))
   (let ((stacker-info (stx-account tx-sender))
         (amount-stacked (get locked stacker-info))
         (amount-unlocked (get unlocked stacker-info))
         (unlock-height (get unlock-height stacker-info))
         (cur-cycle (current-pox-reward-cycle))
         (first-increased-cycle (+ cur-cycle u1))
         (stacker-state (unwrap! (map-get? stacking-state
                                          { stacker: tx-sender })
                                          (err ERR_STACK_INCREASE_NOT_LOCKED)))
         (cur-pox-addr (get pox-addr stacker-state))
         (cur-period (get lock-period stacker-state)))
      ;; tx-sender must be currently locked
      (asserts! (> amount-stacked u0)
                (err ERR_STACK_INCREASE_NOT_LOCKED))
      ;; must be called with positive `increase-by`
      (asserts! (>= increase-by u1)
                (err ERR_STACKING_INVALID_AMOUNT))
      ;; stacker must have enough stx to lock
      (asserts! (>= amount-unlocked increase-by)
                (err ERR_STACKING_INSUFFICIENT_FUNDS))
      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
                (err ERR_STACKING_PERMISSION_DENIED))
      ;; stacker must be directly stacking
      (asserts! (> (len (get reward-set-indexes stacker-state)) u0)
                (err ERR_STACKING_IS_DELEGATED))
      ;; stacker must not be delegating
      (asserts! (is-none (get delegated-to stacker-state))
                (err ERR_STACKING_IS_DELEGATED))

      ;; Validate that amount is less than or equal to `max-amount`
      (asserts! (>= max-amount (+ increase-by amount-stacked)) (err ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH))

      ;; Verify signature from delegate that allows this sender for this cycle
      (try! (consume-signer-key-authorization cur-pox-addr cur-cycle "stack-increase" cur-period signer-sig signer-key increase-by max-amount auth-id))

      ;; update reward cycle amounts
      (asserts! (is-some (fold increase-reward-cycle-entry
            (get reward-set-indexes stacker-state)
            (some { first-cycle: first-increased-cycle,
                    reward-cycle: (get first-reward-cycle stacker-state),
                    stacker: tx-sender,
                    add-amount: increase-by,
                    signer-key: signer-key })))
            (err ERR_INVALID_INCREASE))
      ;; NOTE: stacking-state map is unchanged: it does not track amount-stacked in PoX-4
      (ok { stacker: tx-sender, total-locked: (+ amount-stacked increase-by)})))

;; Extend an active Stacking lock.
;; *New in Stacks 2.1*
;; This method extends the `tx-sender`'s current lockup for an additional `extend-count`
;;    and associates `pox-addr` with the rewards, The `signer-key` will be the key
;;    used for signing. The `tx-sender` can thus decide to change the key when extending.
;; 
;; Because no additional STX are locked in this function, the `amount` field used
;; to verify the signer key authorization is zero. Refer to `verify-signer-key-sig` for more information.
(define-public (stack-extend (extend-count uint)
                             (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                             (signer-sig (optional (buff 65)))
                             (signer-key (buff 33))
                             (max-amount uint)
                             (auth-id uint))
   (let ((stacker-info (stx-account tx-sender))
         ;; to extend, there must already be an etry in the stacking-state
         (stacker-state (unwrap! (get-stacker-info tx-sender) (err ERR_STACK_EXTEND_NOT_LOCKED)))
         (amount-ustx (get locked stacker-info))
         (unlock-height (get unlock-height stacker-info))
         (cur-cycle (current-pox-reward-cycle))
         ;; first-extend-cycle will be the cycle in which tx-sender *would have* unlocked
         (first-extend-cycle (burn-height-to-reward-cycle unlock-height))
         ;; new first cycle should be max(cur-cycle, stacker-state.first-reward-cycle)
         (cur-first-reward-cycle (get first-reward-cycle stacker-state))
         (first-reward-cycle (if (> cur-cycle cur-first-reward-cycle) cur-cycle cur-first-reward-cycle)))

    ;; must be called with positive extend-count
    (asserts! (>= extend-count u1)
              (err ERR_STACKING_INVALID_LOCK_PERIOD))

    ;; stacker must be directly stacking
      (asserts! (> (len (get reward-set-indexes stacker-state)) u0)
                (err ERR_STACKING_IS_DELEGATED))

    ;; stacker must not be delegating
    (asserts! (is-none (get delegated-to stacker-state))
              (err ERR_STACKING_IS_DELEGATED))

    ;; Verify signature from delegate that allows this sender for this cycle
    (try! (consume-signer-key-authorization pox-addr cur-cycle "stack-extend" extend-count signer-sig signer-key u0 max-amount auth-id))

    (let ((last-extend-cycle  (- (+ first-extend-cycle extend-count) u1))
          (lock-period (+ u1 (- last-extend-cycle first-reward-cycle)))
          (new-unlock-ht (reward-cycle-to-burn-height (+ u1 last-extend-cycle))))

      ;; first cycle must be after the current cycle
      (asserts! (> first-extend-cycle cur-cycle) (err ERR_STACKING_INVALID_LOCK_PERIOD))
      ;; lock period must be positive
      (asserts! (> lock-period u0) (err ERR_STACKING_INVALID_LOCK_PERIOD))

      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
                (err ERR_STACKING_PERMISSION_DENIED))

      ;; tx-sender must be locked
      (asserts! (> amount-ustx u0)
        (err ERR_STACK_EXTEND_NOT_LOCKED))

      ;; tx-sender must not be delegating
      (asserts! (is-none (get-check-delegation tx-sender))
        (err ERR_STACKING_ALREADY_DELEGATED))

      ;; standard can-stack-stx checks
      (try! (can-stack-stx pox-addr amount-ustx first-extend-cycle lock-period))

      ;; register the PoX address with the amount stacked
      ;;   for the new cycles
      (let ((extended-reward-set-indexes (try! (add-pox-addr-to-reward-cycles pox-addr first-extend-cycle extend-count amount-ustx tx-sender signer-key)))
            (reward-set-indexes
                ;; use the active stacker state and extend the existing reward-set-indexes
                (let ((cur-cycle-index (- first-reward-cycle (get first-reward-cycle stacker-state)))
                      (old-indexes (get reward-set-indexes stacker-state))
                      ;; build index list by taking the old-indexes starting from cur cycle
                      ;;  and adding the new indexes to it. this way, the index is valid starting from the current cycle
                      (new-list (concat (default-to (list) (slice? old-indexes cur-cycle-index (len old-indexes)))
                                        extended-reward-set-indexes)))
                  (unwrap-panic (as-max-len? new-list u12)))))
          ;; update stacker record
          (map-set stacking-state
            { stacker: tx-sender }
            { pox-addr: pox-addr,
              reward-set-indexes: reward-set-indexes,
              first-reward-cycle: first-reward-cycle,
              lock-period: lock-period,
              delegated-to: none })

        ;; return lock-up information
        (ok { stacker: tx-sender, unlock-burn-height: new-unlock-ht })))))

;; As a delegator, increase an active Stacking lock, issuing a "partial commitment" for the
;;   increased cycles.
;; *New in Stacks 2.1*
;; This method increases `stacker`'s current lockup and partially commits the additional
;;   STX to `pox-addr`
(define-public (delegate-stack-increase
                    (stacker principal)
                    (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                    (increase-by uint))
    (let ((stacker-info (stx-account stacker))
          (existing-lock (get locked stacker-info))
          (available-stx (get unlocked stacker-info))
          (unlock-height (get unlock-height stacker-info)))

     ;; must be called with positive `increase-by`
     (asserts! (>= increase-by u1)
               (err ERR_STACKING_INVALID_AMOUNT))

     (let ((unlock-in-cycle (burn-height-to-reward-cycle unlock-height))
           (cur-cycle (current-pox-reward-cycle))
           (first-increase-cycle (+ cur-cycle u1))
           (last-increase-cycle (- unlock-in-cycle u1))
           (cycle-count (try! (if (<= first-increase-cycle last-increase-cycle)
                                  (ok (+ u1 (- last-increase-cycle first-increase-cycle)))
                                  (err ERR_STACKING_INVALID_LOCK_PERIOD))))
           (new-total-locked (+ increase-by existing-lock))
           (stacker-state
                (unwrap! (map-get? stacking-state { stacker: stacker })
                 (err ERR_STACK_INCREASE_NOT_LOCKED))))

      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
        (err ERR_STACKING_PERMISSION_DENIED))

      ;; stacker must not be directly stacking
      (asserts! (is-eq (len (get reward-set-indexes stacker-state)) u0)
                (err ERR_STACKING_NOT_DELEGATED))

      ;; stacker must be delegated to tx-sender
      (asserts! (is-eq (unwrap! (get delegated-to stacker-state)
                                (err ERR_STACKING_NOT_DELEGATED))
                       tx-sender)
                (err ERR_STACKING_PERMISSION_DENIED))

      ;; stacker must be currently locked
      (asserts! (> existing-lock u0)
        (err ERR_STACK_INCREASE_NOT_LOCKED))

      ;; stacker must have enough stx to lock
      (asserts! (>= available-stx increase-by)
        (err ERR_STACKING_INSUFFICIENT_FUNDS))

      ;; stacker must have delegated to the caller
      (let ((delegation-info (unwrap! (get-check-delegation stacker) (err ERR_STACKING_PERMISSION_DENIED)))
            (delegated-to (get delegated-to delegation-info))
            (delegated-amount (get amount-ustx delegation-info))
            (delegated-pox-addr (get pox-addr delegation-info))
            (delegated-until (get until-burn-ht delegation-info)))
        ;; must have delegated to tx-sender
        (asserts! (is-eq delegated-to tx-sender)
                  (err ERR_STACKING_PERMISSION_DENIED))
        ;; must have delegated enough stx
        (asserts! (>= delegated-amount new-total-locked)
                  (err ERR_DELEGATION_TOO_MUCH_LOCKED))
        ;; if pox-addr is set, must be equal to pox-addr
        (asserts! (match delegated-pox-addr
                         specified-pox-addr (is-eq pox-addr specified-pox-addr)
                         true)
                  (err ERR_DELEGATION_POX_ADDR_REQUIRED))
        ;; delegation must not expire before lock period
        (asserts! (match delegated-until
                        until-burn-ht
                            (>= until-burn-ht unlock-height)
                        true)
                  (err ERR_DELEGATION_EXPIRES_DURING_LOCK)))

      ;; delegate stacking does minimal-can-stack-stx
      (try! (minimal-can-stack-stx pox-addr new-total-locked first-increase-cycle (+ u1 (- last-increase-cycle first-increase-cycle))))

      ;; register the PoX address with the amount stacked via partial stacking
      ;;   before it can be included in the reward set, this must be committed!
      (add-pox-partial-stacked pox-addr first-increase-cycle cycle-count increase-by)

      ;; stacking-state is unchanged, so no need to update

      ;; return the lock-up information, so the node can actually carry out the lock.
      (ok { stacker: stacker, total-locked: new-total-locked}))))

;; As a delegator, extend an active stacking lock, issuing a "partial commitment" for the
;;   extended-to cycles.
;; *New in Stacks 2.1*
;; This method extends `stacker`'s current lockup for an additional `extend-count`
;;    and partially commits those new cycles to `pox-addr`
(define-public (delegate-stack-extend
                    (stacker principal)
                    (pox-addr { version: (buff 1), hashbytes: (buff 32) })
                    (extend-count uint))
    (let ((stacker-info (stx-account stacker))
          ;; to extend, there must already be an entry in the stacking-state
          (stacker-state (unwrap! (get-stacker-info stacker) (err ERR_STACK_EXTEND_NOT_LOCKED)))
          (amount-ustx (get locked stacker-info))
          (unlock-height (get unlock-height stacker-info))
          ;; first-extend-cycle will be the cycle in which tx-sender *would have* unlocked
          (first-extend-cycle (burn-height-to-reward-cycle unlock-height))
          (cur-cycle (current-pox-reward-cycle))
          ;; new first cycle should be max(cur-cycle, stacker-state.first-reward-cycle)
          (cur-first-reward-cycle (get first-reward-cycle stacker-state))
          (first-reward-cycle (if (> cur-cycle cur-first-reward-cycle) cur-cycle cur-first-reward-cycle)))

     ;; must be called with positive extend-count
     (asserts! (>= extend-count u1)
               (err ERR_STACKING_INVALID_LOCK_PERIOD))

     (let ((last-extend-cycle  (- (+ first-extend-cycle extend-count) u1))
           (lock-period (+ u1 (- last-extend-cycle first-reward-cycle)))
           (new-unlock-ht (reward-cycle-to-burn-height (+ u1 last-extend-cycle))))

      ;; first cycle must be after the current cycle
      (asserts! (> first-extend-cycle cur-cycle) (err ERR_STACKING_INVALID_LOCK_PERIOD))
      ;; lock period must be positive
      (asserts! (> lock-period u0) (err ERR_STACKING_INVALID_LOCK_PERIOD))

      ;; must be called directly by the tx-sender or by an allowed contract-caller
      (asserts! (check-caller-allowed)
        (err ERR_STACKING_PERMISSION_DENIED))

      ;; stacker must not be directly stacking
      (asserts! (is-eq (len (get reward-set-indexes stacker-state)) u0)
                (err ERR_STACKING_NOT_DELEGATED))

      ;; stacker must be delegated to tx-sender
      (asserts! (is-eq (unwrap! (get delegated-to stacker-state)
                                (err ERR_STACKING_NOT_DELEGATED))
                       tx-sender)
                (err ERR_STACKING_PERMISSION_DENIED))

      ;; check valid lock period
      (asserts! (check-pox-lock-period lock-period)
        (err ERR_STACKING_INVALID_LOCK_PERIOD))

      ;; stacker must be currently locked
      (asserts! (> amount-ustx u0)
        (err ERR_STACK_EXTEND_NOT_LOCKED))

      ;; stacker must have delegated to the caller
      (let ((delegation-info (unwrap! (get-check-delegation stacker) (err ERR_STACKING_PERMISSION_DENIED))))
        ;; must have delegated to tx-sender
        (asserts! (is-eq (get delegated-to delegation-info) tx-sender)
                  (err ERR_STACKING_PERMISSION_DENIED))
        ;; must have delegated enough stx
        (asserts! (>= (get amount-ustx delegation-info) amount-ustx)
                  (err ERR_DELEGATION_TOO_MUCH_LOCKED))
        ;; if pox-addr is set, must be equal to pox-addr
        (asserts! (match (get pox-addr delegation-info)
                         specified-pox-addr (is-eq pox-addr specified-pox-addr)
                         true)
                  (err ERR_DELEGATION_POX_ADDR_REQUIRED))
        ;; delegation must not expire before lock period
        (asserts! (match (get until-burn-ht delegation-info)
                         until-burn-ht (>= until-burn-ht
                                           new-unlock-ht)
                      true)
                  (err ERR_DELEGATION_EXPIRES_DURING_LOCK))
        )

      ;; delegate stacking does minimal-can-stack-stx
      (try! (minimal-can-stack-stx pox-addr amount-ustx first-extend-cycle lock-period))

      ;; register the PoX address with the amount stacked via partial stacking
      ;;   before it can be included in the reward set, this must be committed!
      (add-pox-partial-stacked pox-addr first-extend-cycle extend-count amount-ustx)

      (map-set stacking-state
        { stacker: stacker }
        { pox-addr: pox-addr,
          reward-set-indexes: (list),
          first-reward-cycle: first-reward-cycle,
          lock-period: lock-period,
          delegated-to: (some tx-sender) })

      ;; return the lock-up information, so the node can actually carry out the lock.
      (ok { stacker: stacker,
            unlock-burn-height: new-unlock-ht }))))

;; Add an authorization for a signer key.
;; When an authorization is added, the `signer-sig` argument is not required
;; in the functions that use it as an argument.
;; The `allowed` flag can be used to either enable or disable the authorization.
;; Only the Stacks principal associated with `signer-key` can call this function.
;;
;; Refer to the documentation for `verify-signer-key-sig` for more information
;; regarding the parameters used in an authorization. When the authorization is used
;; in `stack-stx` and `stack-extend`, the `reward-cycle` refers to the reward cycle
;; where the transaction is confirmed, **not** the reward cycle where stacking begins.
;; The `period` parameter must match the exact lock period (or extend count) used
;; in the stacking transaction. The `max-amount` parameter specifies the maximum amount
;; of STX that can be locked in an individual stacking transaction. `auth-id` is a
;; random uint to prevent replays.
;;
;; *New in Stacks 3.0*
(define-public (set-signer-key-authorization (pox-addr { version: (buff 1), hashbytes: (buff 32)})
                                             (period uint)
                                             (reward-cycle uint)
                                             (topic (string-ascii 14))
                                             (signer-key (buff 33))
                                             (allowed bool)
                                             (max-amount uint)
                                             (auth-id uint))
  (begin
    ;; must be called directly by the tx-sender or by an allowed contract-caller
    (asserts! (check-caller-allowed)
      (err ERR_NOT_ALLOWED))
    ;; Validate that `tx-sender` has the same pubkey hash as `signer-key`
    (asserts! (is-eq
      (unwrap! (principal-construct? (if is-in-mainnet STACKS_ADDR_VERSION_MAINNET STACKS_ADDR_VERSION_TESTNET) (hash160 signer-key)) (err ERR_INVALID_SIGNER_KEY))
      tx-sender) (err ERR_NOT_ALLOWED))
    ;; Must be called with positive period
    (asserts! (>= period u1) (err ERR_STACKING_INVALID_LOCK_PERIOD))
    ;; Must be current or future reward cycle
    (asserts! (>= reward-cycle (current-pox-reward-cycle)) (err ERR_INVALID_REWARD_CYCLE))
    (map-set signer-key-authorizations { pox-addr: pox-addr, period: period, reward-cycle: reward-cycle, topic: topic, signer-key: signer-key, auth-id: auth-id, max-amount: max-amount } allowed)
    (ok allowed)))

;; Get the _current_ PoX stacking delegation information for a stacker.  If the information
;; is expired, or if there's never been such a stacker, then returns none.
;; *New in Stacks 2.1*
(define-read-only (get-delegation-info (stacker principal))
    (get-check-delegation stacker)
)

;; Get the burn height at which a particular contract is allowed to stack for a particular principal.
;; *New in Stacks 2.1*
;; Returns (some (some X)) if X is the burn height at which the allowance terminates
;; Returns (some none) if the caller is allowed indefinitely
;; Returns none if there is no allowance record
(define-read-only (get-allowance-contract-callers (sender principal) (calling-contract principal))
    (map-get? allowance-contract-callers { sender: sender, contract-caller: calling-contract })
)

;; How many PoX addresses in this reward cycle?
;; *New in Stacks 2.1*
(define-read-only (get-num-reward-set-pox-addresses (reward-cycle uint))
    (match (map-get? reward-cycle-pox-address-list-len { reward-cycle: reward-cycle })
        num-addrs
            (get len num-addrs)
        u0
    )
)

;; How many uSTX have been locked up for this address so far, before the delegator commits them?
;; *New in Stacks 2.1*
(define-read-only (get-partial-stacked-by-cycle (pox-addr { version: (buff 1), hashbytes: (buff 32) }) (reward-cycle uint) (sender principal))
    (map-get? partial-stacked-by-cycle { pox-addr: pox-addr, reward-cycle: reward-cycle, sender: sender })
)
