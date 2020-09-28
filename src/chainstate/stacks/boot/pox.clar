;; The .pox contract
;; Error codes
(define-constant ERR_STACKING_UNREACHABLE 255)
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
(define-constant ERR_STACKING_ALREADY_REJECTED 17)
(define-constant ERR_STACKING_INVALID_AMOUNT 18)
(define-constant ERR_NOT_ALLOWED 19)

;; PoX disabling threshold (a percent)
(define-constant POX_REJECTION_FRACTION u25)

;; Data vars that store a copy of the burnchain configuration.
;; Implemented as data-vars, so that different configurations can be
;; used in e.g. test harnesses.
(define-data-var pox-prepare-cycle-length uint PREPARE_CYCLE_LENGTH)
(define-data-var pox-reward-cycle-length uint REWARD_CYCLE_LENGTH)
(define-data-var pox-rejection-fraction uint POX_REJECTION_FRACTION)
(define-data-var first-burnchain-block-height uint u0)
(define-data-var configured bool false)

;; This function can only be called once, when it boots up
(define-public (set-burnchain-parameters (first-burn-height uint) (prepare-cycle-length uint) (reward-cycle-length uint) (rejection-fraction uint))
    (begin
        (asserts! (and is-in-regtest (not (var-get configured))) (err ERR_NOT_ALLOWED))
        (var-set first-burnchain-block-height first-burn-height)
        (var-set pox-prepare-cycle-length prepare-cycle-length)
        (var-set pox-reward-cycle-length reward-cycle-length)
        (var-set pox-rejection-fraction rejection-fraction)
        (var-set configured true)
        (ok true))
)

;; The Stacking lock-up state and associated metadata.
;; Records can be inserted into this map via one of two ways:
;; * via contract-call? to the (stack-stx) method, or
;; * via a transaction in the underlying burnchain that encodes the same data.
;; In the latter case, this map will be updated by the Stacks
;; node itself, and transactions in the burnchain will take priority
;; over transactions in the Stacks chain when processing this block.
(define-map stacking-state
    ((stacker principal))
    (
        ;; how many uSTX locked?
        (amount-ustx uint)
        ;; Description of the underlying burnchain address that will
        ;; receive PoX'ed tokens. Translating this into an address
        ;; depends on the burnchain being used.  When Bitcoin is
        ;; the burnchain, this gets translated into a p2pkh, p2sh,
        ;; p2wpkh-p2sh, or p2wsh-p2sh UTXO, depending on the version.
        (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
        ;; how long the uSTX are locked, in reward cycles.
        (lock-period uint)
        ;; reward cycle when rewards begin
        (first-reward-cycle uint)
    )
)

;; How many uSTX are stacked in a given reward cycle.
;; Updated when a new PoX address is registered, or when more STX are granted
;; to it.
(define-map reward-cycle-total-stacked
    ((reward-cycle uint))
    ((total-ustx uint))
)

;; Internal map read by the Stacks node to iterate through the list of
;; PoX reward addresses on a per-reward-cycle basis.
(define-map reward-cycle-pox-address-list
    ((reward-cycle uint) (index uint))
    (
        (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
        (total-ustx uint)
    )
)

(define-map reward-cycle-pox-address-list-len
    ((reward-cycle uint))
    ((len uint))
)

;; When is a PoX address active?
;; Used to check of a PoX address is registered or not in a given
;; reward cycle.
(define-map pox-addr-reward-cycles
    ((pox-addr (tuple (version (buff 1)) (hashbytes (buff 20)))))
    (
        (first-reward-cycle uint)
        (num-cycles uint)
    )
)

;; Amount of uSTX that reject PoX, by reward cycle
(define-map stacking-rejection
    ((reward-cycle uint))
    ((amount uint))
)

;; Who rejected in which reward cycle
(define-map stacking-rejectors
    ((stacker principal) (reward-cycle uint))
    ((amount uint))
)

;; Getter for stacking-rejectors
(define-read-only (get-pox-rejection (stacker principal) (reward-cycle uint))
    (map-get? stacking-rejectors { stacker: stacker, reward-cycle: reward-cycle }))

;; Has PoX been rejected in the given reward cycle?
(define-read-only (is-pox-active (reward-cycle uint))
    (let (
        (reject-votes 
            (default-to
                u0
                (get amount (map-get? stacking-rejection { reward-cycle: reward-cycle }))))
    )
    ;; (100 * reject-votes) / stx-liquid-supply < pox-rejection-fraction    
    (< (* u100 reject-votes) 
       (* (var-get pox-rejection-fraction) stx-liquid-supply)))
)

;; What's the reward cycle number of the burnchain block height?
;; Will runtime-abort if height is less than the first burnchain block (this is intentional)
(define-private (burn-height-to-reward-cycle (height uint)) 
    (/ (- height (var-get first-burnchain-block-height)) (var-get pox-reward-cycle-length)))

;; What's the block height at the start of a given reward cycle?
(define-private (reward-cycle-to-burn-height (cycle uint))
    (+ (var-get first-burnchain-block-height) (* cycle (var-get pox-reward-cycle-length))))

;; What's the current PoX reward cycle?
(define-private (current-pox-reward-cycle)
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
    )
)

;; Get the size of the reward set for a reward cycle.
;; Note that this does _not_ return duplicate PoX addresses.
;; Note that this also _will_ return PoX addresses that are beneath
;; the minimum threshold -- i.e. the threshold can increase after insertion.
;; Used internally by the Stacks node, which filters out the entries
;; in this map to select PoX addresses with enough STX.
(define-read-only (get-reward-set-size (reward-cycle uint))
    (default-to
        u0
        (get len (map-get? reward-cycle-pox-address-list-len { reward-cycle: reward-cycle }))))

;; Is a PoX address registered anywhere in a given range of reward cycles?
;; Checkes the integer range [reward-cycle-start, reward-cycle-start + num-cycles)
;; Returns true if it's registered in at least one reward cycle in the given range.
;; Returns false if it's not registered in any reward cycle in the given range.
(define-private (is-pox-addr-registered (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
                                        (reward-cycle-start uint)
                                        (num-cycles uint))
    (let (
        (pox-addr-range-opt (map-get? pox-addr-reward-cycles { pox-addr: pox-addr }))
    )
    (match pox-addr-range-opt
        ;; some range
        pox-addr-range
            (and (>= (+ reward-cycle-start num-cycles) (get first-reward-cycle pox-addr-range))
                    (< reward-cycle-start (+ (get first-reward-cycle pox-addr-range) (get num-cycles pox-addr-range))))
        ;; none
        false
    ))
)

;; How many rejection votes have we been accumulating for the next block
(define-private (next-cycle-rejection-votes)
    (default-to
        u0
        (get amount (map-get? stacking-rejection { reward-cycle: (+ u1 (current-pox-reward-cycle)) }))))

;; Add a single PoX address to a single reward cycle.
;; Used to build up a set of per-reward-cycle PoX addresses.
;; No checking will be done -- don't call if this PoX address is already registered in this reward cycle!
(define-private (append-reward-cycle-pox-addr (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
                                              (reward-cycle uint)
                                              (amount-ustx uint))
    (let (
        (sz (get-reward-set-size reward-cycle))
    )
    (map-set reward-cycle-pox-address-list
        { reward-cycle: reward-cycle, index: sz }
        { pox-addr: pox-addr, total-ustx: amount-ustx })
    (map-set reward-cycle-pox-address-list-len
        { reward-cycle: reward-cycle }
        { len: (+ u1 sz) })
    (+ u1 sz))
)

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

;; Add a PoX address to the ith reward cycle, if i is between 0 and the given num-cycles (exclusive).
;; Arguments are given as a tuple, so this function can be (map ..)'ed onto a list of its arguments.
;; Used by add-pox-addr-to-reward-cycles.
;; No checking is done.
;; Returns 1 if added.
;; Returns 0 if not added.
(define-private (add-pox-addr-to-ith-reward-cycle (cycle-index uint) (params (tuple 
                                                            (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
                                                            (first-reward-cycle uint)
                                                            (num-cycles uint)
                                                            (amount-ustx uint)
                                                            (i uint))))
    (let ((reward-cycle (+ (get first-reward-cycle params) (get i params)))
          (i (get i params)))
    {
        pox-addr: (get pox-addr params),
        first-reward-cycle: (get first-reward-cycle params),
        num-cycles: (get num-cycles params),
        amount-ustx: (get amount-ustx params),
        i: (if (< i (get num-cycles params))
            (let ((total-ustx (get-total-ustx-stacked reward-cycle)))
              ;; record how many uSTX this pox-addr will stack for in the given reward cycle
              (append-reward-cycle-pox-addr
                (get pox-addr params)
                reward-cycle
                (get amount-ustx params))

              ;; update running total
              (map-set reward-cycle-total-stacked
                 { reward-cycle: reward-cycle }
                 { total-ustx: (+ (get amount-ustx params) total-ustx) })

              ;; updated _this_ reward cycle
              (+ i u1))
            (+ i u0))
    }))

;; Add a PoX address to a given sequence of reward cycle lists.
;; A PoX address can be added to at most 12 consecutive cycles.
;; No checking is done.
;; Returns the number of reward cycles added
(define-private (add-pox-addr-to-reward-cycles (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
                                               (first-reward-cycle uint)
                                               (num-cycles uint)
                                               (amount-ustx uint))
    (let (
        (cycle-indexes (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11))
    )
    ;; For safety, add up the number of times (add-principal-to-ith-reward-cycle) returns 1.
    ;; It _should_ be equal to num-cycles.
    (asserts! 
        (is-eq num-cycles (get i 
            (fold add-pox-addr-to-ith-reward-cycle cycle-indexes 
                { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u0 })))
        (err ERR_STACKING_UNREACHABLE))

    ;; mark address in use over this range
    (map-set pox-addr-reward-cycles
        { pox-addr: pox-addr }
        { first-reward-cycle: first-reward-cycle, num-cycles: num-cycles }
    )
    (ok true)
    )
)

;; What is the minimum number of uSTX to be stacked in the given reward cycle?
;; Used internally by the Stacks node, and visible publicly.
(define-read-only (get-stacking-minimum)
    (/ stx-liquid-supply u20000)
)

;; Is the address mode valid for a PoX burn address?
(define-private (check-pox-addr-version (version (buff 1)))
    (or (is-eq version ADDRESS_VERSION_P2PKH)
        (is-eq version ADDRESS_VERSION_P2SH)
        (is-eq version ADDRESS_VERSION_P2WPKH)
        (is-eq version ADDRESS_VERSION_P2WSH)))

;; Is the given lock period valid?
(define-private (check-pox-lock-period (lock-period uint)) 
    (and (>= lock-period MIN_POX_REWARD_CYCLES) 
         (<= lock-period MAX_POX_REWARD_CYCLES)))

;; Evaluate if a participant can stack an amount of STX for a given period.
;; This method is designed as a read-only method so that it can be used as 
;; a set of guard conditions and also as a read-only RPC call that can be
;; performed beforehand.
(define-read-only (can-stack-stx (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
                                  (amount-ustx uint)
                                  (first-reward-cycle uint)
                                  (num-cycles uint))
    (let ((is-registered (is-pox-addr-registered pox-addr first-reward-cycle num-cycles)))
      ;; amount must be valid
      (asserts! (> amount-ustx u0)
          (err ERR_STACKING_INVALID_AMOUNT))

      ;; tx-sender principal must not have rejected in this upcoming reward cycle
      (asserts! (is-none (get-pox-rejection tx-sender first-reward-cycle))
          (err ERR_STACKING_ALREADY_REJECTED))

      ;; can't be registered yet
      (asserts! (not is-registered)
          (err ERR_STACKING_POX_ADDRESS_IN_USE))

      ;; the Stacker must have sufficient unlocked funds
      (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
          (err ERR_STACKING_INSUFFICIENT_FUNDS))

      ;; minimum uSTX must be met
      (asserts! (<= (get-stacking-minimum) amount-ustx)
          (err ERR_STACKING_THRESHOLD_NOT_MET))

      ;; lock period must be in acceptable range.
      (asserts! (check-pox-lock-period num-cycles)
          (err ERR_STACKING_INVALID_LOCK_PERIOD))

      ;; address version must be valid
      (asserts! (check-pox-addr-version (get version pox-addr))
          (err ERR_STACKING_INVALID_POX_ADDRESS))

      (ok true))
)

;; Lock up some uSTX for stacking!  Note that the given amount here is in micro-STX (uSTX).
;; The STX will be locked for the given number of reward cycles (lock-period).
;; This is the self-service interface.  tx-sender will be the Stacker.
;;
;; * The given stacker cannot currently be stacking.
;; * You will need the minimum uSTX threshold.  This will be determined by (get-stacking-minimum)
;; at the time this method is called.
;; * You may need to increase the amount of uSTX locked up later, since the minimum uSTX threshold
;; may increase between reward cycles.
;;
;; The tokens will unlock and be returned to the Stacker (tx-sender) automatically.
(define-public (stack-stx (amount-ustx uint)
                          (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
                          (lock-period uint))
    ;; this stacker's first reward cycle is the _next_ reward cycle
    (let ((first-reward-cycle (+ u1 (current-pox-reward-cycle))))

      ;; tx-sender principal must not be stacking
      (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR_STACKING_ALREADY_STACKED))

      ;; ensure that stacking can be performed
      (try! (can-stack-stx pox-addr amount-ustx first-reward-cycle lock-period))

      ;; register the PoX address with the amount stacked
      (try! (add-pox-addr-to-reward-cycles pox-addr first-reward-cycle lock-period amount-ustx))

      ;; add stacker record
      (map-set stacking-state
        { stacker: tx-sender }
        {
          amount-ustx: amount-ustx,
          pox-addr: pox-addr,
          first-reward-cycle: first-reward-cycle,
          lock-period: lock-period })

      ;; return the lock-up information, so the node can actually carry out the lock. 
      (ok { stacker: tx-sender, lock-amount: amount-ustx, unlock-burn-height: (reward-cycle-to-burn-height (+ first-reward-cycle lock-period)) }))
)

;; Reject Stacking for this reward cycle.
;; tx-sender votes all its uSTX for rejection.
;; Note that unlike PoX, rejecting PoX does not lock the tx-sender's
;; tokens.  PoX rejection acts like a coin vote.
(define-public (reject-pox)
    (let (
        (balance (stx-get-balance tx-sender))
        (vote-reward-cycle (+ u1 (current-pox-reward-cycle)))
    )

    ;; tx-sender principal must not have rejected in this upcoming reward cycle
    (asserts! (is-none (get-pox-rejection tx-sender vote-reward-cycle))
        (err ERR_STACKING_ALREADY_REJECTED))

    ;; tx-sender can't be a stacker
    (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR_STACKING_ALREADY_STACKED))

    ;; vote for rejection
    (map-set stacking-rejection
        { reward-cycle: vote-reward-cycle }
        { amount: (+ (next-cycle-rejection-votes) balance) }
    )

    ;; mark voted
    (map-set stacking-rejectors
        { stacker: tx-sender, reward-cycle: vote-reward-cycle }
        { amount: balance }
    )

    (ok true))
)

;; Used for PoX parameters discovery
(define-read-only (get-pox-info)
    (ok {
        min-amount-ustx: (get-stacking-minimum),
        reward-cycle-id: (current-pox-reward-cycle),
        prepare-cycle-length: (var-get pox-prepare-cycle-length),
        first-burnchain-block-height: (var-get first-burnchain-block-height),
        reward-cycle-length: (var-get pox-reward-cycle-length),
        rejection-fraction: (var-get pox-rejection-fraction),
        current-rejection-votes: (next-cycle-rejection-votes),
        total-liquid-supply-ustx: stx-liquid-supply,
    })
)