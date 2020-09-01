;; The .pox contract
;; Error codes
(define-constant ERR-STACKING-UNREACHABLE 255)
(define-constant ERR-STACKING-INSUFFICIENT-FUNDS 1)
(define-constant ERR-STACKING-INVALID-LOCK-PERIOD 2)
(define-constant ERR-STACKING-ALREADY-STACKED 3)
(define-constant ERR-STACKING-NO-SUCH-PRINCIPAL 4)
(define-constant ERR-STACKING-EXPIRED 5)
(define-constant ERR-STACKING-STX-LOCKED 6)
(define-constant ERR-STACKING-NO-SUCH-DELEGATE 7)
(define-constant ERR-STACKING-BAD-DELEGATE 8)
(define-constant ERR-STACKING-PERMISSION-DENIED 9)
(define-constant ERR-STACKING-INVALID-DELEGATE-TENURE 10)
(define-constant ERR-STACKING-THRESHOLD-NOT-MET 11)
(define-constant ERR-STACKING-POX-ADDRESS-IN-USE 12)
(define-constant ERR-STACKING-INVALID-POX-ADDRESS 13)
(define-constant ERR-STACKING-ALREADY-DELEGATED 14)
(define-constant ERR-STACKING-DELEGATE-ALREADY-REGISTERED 15)
(define-constant ERR-STACKING-DELEGATE-EXPIRED 16)
(define-constant ERR-STACKING-ALREADY-REJECTED 17)
(define-constant ERR-STACKING-INVALID-AMOUNT 18)
(define-constant ERR-NOT-ALLOWED 19)

;; Min/max number of reward cycles uSTX can be locked for
(define-constant MIN-POX-REWARD-CYCLES u1)
(define-constant MAX-POX-REWARD-CYCLES u12)

;; Default length of the PoX registration window, in burnchain blocks.
(define-constant REGISTRATION-WINDOW-LENGTH u250)

;; Default length of the PoX reward cycle, in burnchain blocks.
(define-constant REWARD-CYCLE-LENGTH u1000)

;; Valid values for burnchain address versions.
;; These correspond to address hash modes in Stacks 2.0.
(define-constant ADDRESS-VERSION-P2PKH u0)
(define-constant ADDRESS-VERSION-P2SH u1)
(define-constant ADDRESS-VERSION-P2WPKH u2)
(define-constant ADDRESS-VERSION-P2WSH u3)

;; Stacking thresholds
(define-constant STACKING-THRESHOLD-25 u20000)
(define-constant STACKING-THRESHOLD-100 u5000)

;; PoX disabling threshold (a percent)
(define-constant POX-REJECTION-FRACTION u25)

;; Data vars that store a copy of the burnchain configuration.
;; Implemented as data-vars, so that different configurations can be
;; used in e.g. test harnesses.
(define-data-var pox-registration-window-length uint REGISTRATION-WINDOW-LENGTH)
(define-data-var pox-reward-cycle-length uint REWARD-CYCLE-LENGTH)
(define-data-var pox-rejection-fraction uint POX-REJECTION-FRACTION)
(define-data-var first-burnchain-block-height uint u0)
(define-data-var configured bool false)

;; This function can only be called once, when it boots up
(define-public (set-burnchain-parameters (first-burn-height uint) (pox-reg-window-len uint) (pox-reward-cycle-len uint) (pox-rejection-frac uint))
    (begin
        (asserts! (and is-in-regtest (not (var-get configured))) (err ERR-NOT-ALLOWED))
        (var-set first-burnchain-block-height first-burn-height)
        (var-set pox-registration-window-length pox-reg-window-len)
        (var-set pox-reward-cycle-length pox-reward-cycle-len)
        (var-set pox-rejection-fraction pox-rejection-frac)
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
        (pox-addr (tuple (version uint) (hashbytes (buff 20))))
        ;; how long the uSTX are locked, in reward cycles.
        (lock-period uint)
        ;; reward cycle when rewards begin
        (first-reward-cycle uint)
        ;; Who, if anyone, is the delegate for this account?
        ;; The delegate may begin Stacking on behalf of the
        ;; locked-up STX tokens.
        (delegate (optional principal))
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
        (pox-addr (tuple (version uint) (hashbytes (buff 20))))
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
    ((pox-addr (tuple (version uint) (hashbytes (buff 20)))))
    (
        (first-reward-cycle uint)
        (num-cycles uint)
    )
)

;; Binding between the principal whose tokens are stacked, and the principal who
;; is allowed to set the PoX reward address.  This binding also includes permissions
;; that the delegator has, as described below.
(define-map delegates
    ;; The address of who owns the tokens to be stacked.
    ((stacker principal))
    (
        ;; The address of the delegate, who stacks them.
        (delegate principal)
        ;; Number of uSTX this delegate may stack on this stacker's behalf.
        (amount-ustx uint)
    )
)

;; Binding between the delegate, and the amount of STX and PoX addresses it 
;; is entrusted with.  Updated when the client delegates STX.
(define-map delegate-control
    ((delegate principal))
    (
        ;; Total number of uSTX locked to this delegate
        (total-ustx uint)
        ;; PoX address the delegate must use.
        (pox-addr (tuple (version uint) (hashbytes (buff 20))))
        ;; Earliest time at which the delegate can Stack the delegated STX.
        (burn-block-height-start uint)
        ;; Beginning of this delegate's tenure
        (first-reward-cycle uint)
        ;; How long the uSTX will be locked for, in reward cycles
        (tenure-cycles uint)
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
    ;; (100 * reject-votes) / total-liquid-ustx < pox-rejection-fraction
    (< (/ (* u100 reject-votes) total-liquid-ustx) (var-get pox-rejection-fraction)))
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
(define-private (is-pox-addr-registered (pox-addr (tuple (version uint) (hashbytes (buff 20))))
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

;; Add a single PoX address to a single reward cycle.
;; Used to build up a set of per-reward-cycle PoX addresses.
;; No checking will be done -- don't call if this PoX address is already registered in this reward cycle!
(define-private (append-reward-cycle-pox-addr (pox-addr (tuple (version uint) (hashbytes (buff 20))))
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
(define-private (add-pox-addr-to-ith-reward-cycle (args (tuple 
                                                            (pox-addr (tuple (version uint) (hashbytes (buff 20))))
                                                            (first-reward-cycle uint)
                                                            (num-cycles uint)
                                                            (amount-ustx uint)
                                                            (i uint))))
    (let (
        (reward-cycle (+ (get first-reward-cycle args) (get i args)))
    )
    (if (< (get i args) (get num-cycles args))
        (let (
            (total-ustx (get-total-ustx-stacked reward-cycle))
        )
        ;; record how many uSTX this pox-addr will stack for in the given reward cycle
        (append-reward-cycle-pox-addr
            (get pox-addr args)
            reward-cycle
            (get amount-ustx args))

        ;; update running total
        (map-set reward-cycle-total-stacked
            { reward-cycle: reward-cycle }
            { total-ustx: (+ (get amount-ustx args) total-ustx) }
        )
        
        ;; updated _this_ reward cycle
        u1)
        u0
    ))
)

;; Add a PoX address to a given sequence of reward cycle lists.
;; A PoX address can be added to at most 12 consecutive cycles.
;; No checking is done.
;; Returns the number of reward cycles added
(define-private (add-pox-addr-to-reward-cycles (pox-addr (tuple (version uint) (hashbytes (buff 20))))
                                               (first-reward-cycle uint)
                                               (num-cycles uint)
                                               (amount-ustx uint))
    (begin
        ;; For safety, add up the number of times (add-principal-to-ith-reward-cycle) returns 1.
        ;; It _should_ be equal to num-cycles.
        (asserts! (is-eq num-cycles (fold +
           (map add-pox-addr-to-ith-reward-cycle (list
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u0 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u1 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u2 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u3 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u4 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u5 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u6 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u7 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u8 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u9 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u10 }
              { pox-addr: pox-addr, first-reward-cycle: first-reward-cycle, num-cycles: num-cycles, amount-ustx: amount-ustx, i: u11 }))
           u0))
           (err ERR-STACKING-UNREACHABLE))

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
(define-read-only (get-stacking-minimum (reward-cycle uint))
    (let (
        (ustx-stacked-so-far (get-total-ustx-stacked reward-cycle))
    )
    (if (< ustx-stacked-so-far (/ total-liquid-ustx u4))
        ;; less than 25% of all liquid STX are stacked, so the threshold is smaller
        (/ total-liquid-ustx STACKING-THRESHOLD-25)
        ;; at least 25% of all liquid STX are stacked, so the threshold is larger
        (/ total-liquid-ustx STACKING-THRESHOLD-100)))
)

;; Is the address mode valid for a PoX burn address?
(define-private (check-pox-addr-version (version uint))
    (and (>= version ADDRESS-VERSION-P2PKH)
         (<= version ADDRESS-VERSION-P2WSH)))

;; Is the given lock period valid?
(define-private (check-pox-lock-period (lock-period uint)) 
    (and (>= lock-period MIN-POX-REWARD-CYCLES) 
         (<= lock-period MAX-POX-REWARD-CYCLES)))

;; Register a PoX address for one or more reward cycles, and set how many uSTX it locks up initially.
;; Will fail if the PoX address is already registered in one of the reward cycles.
;; Will fail if the number of uSTX is beneath the lowest allowed Stacking threshold at the time of the call.
(define-private (register-pox-addr-checked (pox-addr (tuple (version uint) (hashbytes (buff 20))))
                                           (amount-ustx uint)
                                           (first-reward-cycle uint)
                                           (num-cycles uint)
                                           (is-delegate bool))
    (let (
        (ustx-min (get-stacking-minimum first-reward-cycle))
        (is-registered (is-pox-addr-registered pox-addr first-reward-cycle num-cycles))
    )
    ;; can't be registered yet if not a delegate
    ;; (the delegate claims its PoX address when it registers)
    (asserts! (or (not is-registered) is-delegate)
        (err ERR-STACKING-POX-ADDRESS-IN-USE))

    ;; minimum uSTX must be met
    (asserts! (<= ustx-min amount-ustx)
        (err ERR-STACKING-THRESHOLD-NOT-MET))

    ;; lock period must be in acceptable range.
    (asserts! (check-pox-lock-period num-cycles)
        (err ERR-STACKING-INVALID-LOCK-PERIOD))

    ;; address version must be valid
    (asserts! (check-pox-addr-version (get version pox-addr))
        (err ERR-STACKING-INVALID-POX-ADDRESS))

    ;; register address and stacking
    (try! (add-pox-addr-to-reward-cycles pox-addr first-reward-cycle num-cycles amount-ustx))
    (ok true))
)

;; Get the a client stacker's delegate information.
;; Returns (optional principal) -- will be (some ..) if a delegate is registered for the
;; given stacker at the given burn block height, or none if not.
(define-read-only (get-client-delegate-info (client-stacker principal))
    (map-get? delegates { stacker: client-stacker })
)

;; Get the delegate control info
(define-read-only (get-delegate-control-info (delegate principal))
    (map-get? delegate-control { delegate: delegate }))

;; Delegate registration.
;; A delegate must register itself and a PoX address before
;; other Stackers can delegate to it.  It also registers the duration
;; for which its clients' uSTX will be locked.
;; tx-sender is the delegate.
(define-public (register-delegate (pox-addr (tuple (version uint) (hashbytes (buff 20))))
                                  (tenure-burn-block-begin uint)
                                  (tenure-reward-num-cycles uint))
    (let (
        ;; tenure begins in the first full reward cycle after when the tenure burn block passes
        (first-allowed-reward-cycle 
            (+ u1 (burn-height-to-reward-cycle tenure-burn-block-begin)))
    )
    ;; must not be a registered delegate already
    (asserts! (is-none (get-delegate-control-info tx-sender))
        (err ERR-STACKING-DELEGATE-ALREADY-REGISTERED))

    ;; lock period must be in acceptable range.
    (asserts! (check-pox-lock-period tenure-reward-num-cycles)
        (err ERR-STACKING-INVALID-DELEGATE-TENURE))

    ;; PoX address version must be valid
    (asserts! (check-pox-addr-version (get version pox-addr))
        (err ERR-STACKING-INVALID-POX-ADDRESS))

    ;; tenure must start strictly before the first-allowed reward cycle
    (asserts! (< tenure-burn-block-begin (reward-cycle-to-burn-height first-allowed-reward-cycle))
        (err ERR-STACKING-INVALID-DELEGATE-TENURE))

    ;; tenure must start at or after the current burn block height -- no retroactive registration
    (asserts! (<= burn-block-height tenure-burn-block-begin)
        (err ERR-STACKING-INVALID-DELEGATE-TENURE))

    ;; register!
    (map-set delegate-control
        { delegate: tx-sender }
        {
            total-ustx: u0,
            pox-addr: pox-addr,
            burn-block-height-start: tenure-burn-block-begin,
            first-reward-cycle: first-allowed-reward-cycle,
            tenure-cycles: tenure-reward-num-cycles
        }
    )

    ;; claim PoX address up-front
    (map-set pox-addr-reward-cycles
        { pox-addr: pox-addr }
        { first-reward-cycle: first-allowed-reward-cycle, num-cycles: tenure-reward-num-cycles }
    )
    (ok true))
)

;; Delegated uSTX lock-up.
;; The Stacker (the caller) locks up their uSTX, and specifies a delegate
;; configuration to use.  The delegate will then carry out the PoX address
;; registration.
;; Some checks are performed:
;; * The Stacker must not have rejected PoX in the upcoming reward cycle
;; * The Stacker must not currently be Stacking.
;; * The Stacker must have the given amount-ustx funds available.
;; * The Stacker cannot be a delegate
;; * The stacker cannot have a delegate
;; * The delegate's tenure must not have started
;; * The delegate must have not have begun.
;; The tokens will unlock and be returned to the Stacker (tx-sender) automatically once the
;; lockup period ends.
(define-public (delegate-stx (delegate principal)
                             (amount-ustx uint))
    (let (
        (this-contract (as-contract tx-sender))
        
        ;; this stacker's first reward cycle is the _next_ reward cycle
        (first-reward-cycle (+ u1 (current-pox-reward-cycle)))

        ;; existing delegate control record -- the delegate must
        ;; have registered itself.
        (delegate-control-info
           (unwrap!
               (get-delegate-control-info delegate)
               (err ERR-STACKING-NO-SUCH-DELEGATE)))
    )
    ;; amount must be valid
    (asserts! (> amount-ustx u0)
        (err ERR-STACKING-INVALID-AMOUNT))

    ;; tx-sender principal (the Stacker) must not have rejected in this upcoming reward cycle
    (asserts! (is-none (get-pox-rejection tx-sender first-reward-cycle))
        (err ERR-STACKING-ALREADY-REJECTED))

    ;; tx-sender principal (the Stacker) must not be Stacking.
    (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR-STACKING-ALREADY-STACKED))
    
    ;; the Stacker must have no delegate/client relationships
    (asserts! (is-none (get-client-delegate-info tx-sender))
        (err ERR-STACKING-ALREADY-DELEGATED))

    ;; the Stacker must not be registered as a delegate
    (asserts! (is-none (get-delegate-control-info tx-sender))
        (err ERR-STACKING-BAD-DELEGATE))

    ;; the delegate must not have begun stacking yet
    (asserts! (is-none (get-stacker-info delegate))
        (err ERR-STACKING-ALREADY-DELEGATED))

    ;; the delegate's first reward cycle must not have started yet
    (asserts! (< (current-pox-reward-cycle) (get first-reward-cycle delegate-control-info))
        (err ERR-STACKING-DELEGATE-EXPIRED))

    ;; the Stacker must have sufficient unlocked funds
    (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
        (err ERR-STACKING-INSUFFICIENT-FUNDS))

    ;; encode the delegate/client relationship
    (map-set delegates
        { stacker: tx-sender }
        {
            delegate: delegate,
            amount-ustx: amount-ustx
        }
    )

    ;; update how much uSTX the delegate now controls in total
    (map-set delegate-control
        { delegate: delegate }
        {
            total-ustx: (+ amount-ustx (get total-ustx delegate-control-info)),
            pox-addr: (get pox-addr delegate-control-info),
            burn-block-height-start: (get burn-block-height-start delegate-control-info),
            first-reward-cycle: (get first-reward-cycle delegate-control-info),
            tenure-cycles: (get tenure-cycles delegate-control-info)
        }
    )

    ;; add a stacker record for this principal
    (map-set stacking-state
        { stacker: tx-sender }
        {
            amount-ustx: amount-ustx,
            pox-addr: (get pox-addr delegate-control-info),
            first-reward-cycle: first-reward-cycle,
            lock-period: (get tenure-cycles delegate-control-info),
            delegate: (some delegate)
        }
    )

    ;; we're done! let the delgate do its thing.
    ;; Give back the information the node needs to actually carry out the lock.
    (ok { stacker: tx-sender, lock-amount: amount-ustx, unlock-burn-height: (reward-cycle-to-burn-height (+ first-reward-cycle (get tenure-cycles delegate-control-info))) }))
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
                          (pox-addr (tuple (version uint) (hashbytes (buff 20))))
                          (lock-period uint))
    (let (
        (this-contract (as-contract tx-sender))
        
        ;; this stacker's first reward cycle is the _next_ reward cycle
        (first-reward-cycle (+ u1 (current-pox-reward-cycle)))
    )
    ;; amount must be valid
    (asserts! (> amount-ustx u0)
        (err ERR-STACKING-INVALID-AMOUNT))

    ;; tx-sender principal must not have rejected in this upcoming reward cycle
    (asserts! (is-none (get-pox-rejection tx-sender first-reward-cycle))
        (err ERR-STACKING-ALREADY-REJECTED))

    ;; tx-sender principal must not be stacking
    (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR-STACKING-ALREADY-STACKED))

    ;; tx-sender must not have a delegate/client relationship
    (asserts! (is-none (get-client-delegate-info tx-sender))
        (err ERR-STACKING-ALREADY-DELEGATED))

    ;; tx-sender must not be a delegate
    (asserts! (is-none (get-delegate-control-info tx-sender))
        (err ERR-STACKING-BAD-DELEGATE))

    ;; the Stacker must have sufficient unlocked funds
    (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
        (err ERR-STACKING-INSUFFICIENT-FUNDS))
    
    ;; register the PoX address with the amount stacked
    (try!
        (register-pox-addr-checked pox-addr amount-ustx first-reward-cycle lock-period false))

    ;; add stacker record
    (map-set stacking-state
        { stacker: tx-sender }
        {
            amount-ustx: amount-ustx,
            pox-addr: pox-addr,
            first-reward-cycle: first-reward-cycle,
            lock-period: lock-period,
            delegate: none
        }
    )
    
    ;; return the lock-up information, so the node can actually carry out the lock. 
    (ok { stacker: tx-sender, lock-amount: amount-ustx, unlock-burn-height: (reward-cycle-to-burn-height (+ first-reward-cycle lock-period)) }))
)

;; Delegated uSTX lockup, executed by the delegate.
;; The stacker will be the delegate, in place of its clients' uSTX.
;; The delegate can only call this once per stacking tenure.
;; Once called, no future Stackers can add this delegate as their delegate.
;; NOTE: the delegate itself may reject PoX, but still call this method on behalf
;; of its clients.
(define-public (delegate-stack-stx)
    (let (
        ;; delegate must exist
        (delegate-control-info 
            (unwrap!
                (get-delegate-control-info tx-sender)
                (err ERR-STACKING-NO-SUCH-DELEGATE)))
    )
    ;; tx-sender principal is the delegate, and it must not be stacking
    (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR-STACKING-ALREADY-STACKED))

    ;; delegate's first reward cycle must not have begun yet
    (asserts! (< (current-pox-reward-cycle) (get first-reward-cycle delegate-control-info))
        (err ERR-STACKING-DELEGATE-EXPIRED))

    ;; delegate can't call this until the start of its tenure (by burn block height)
    (asserts! (<= (get burn-block-height-start delegate-control-info) burn-block-height)
        (err ERR-STACKING-PERMISSION-DENIED))

    ;; lock it in!
    ;; register the PoX address with the amount stacked
    (try!
        (register-pox-addr-checked
            (get pox-addr delegate-control-info)
            (get total-ustx delegate-control-info)
            (get first-reward-cycle delegate-control-info)
            (get tenure-cycles delegate-control-info)
            true))

    ;; add stacker record for the delegate
    (map-set stacking-state
        { stacker: tx-sender }
        {
            amount-ustx: (get total-ustx delegate-control-info),
            pox-addr: (get pox-addr delegate-control-info),
            first-reward-cycle: (get first-reward-cycle delegate-control-info),
            lock-period: (get tenure-cycles delegate-control-info),
            delegate: none
        }
    )
    
    (ok true))
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
    (let (
        (cur-rejected
            (default-to
                u0
                (get amount (map-get? stacking-rejection { reward-cycle: (+ u1 (current-pox-reward-cycle)) }))))
    )
    ;; tx-sender principal must not have rejected in this upcoming reward cycle
    (asserts! (is-none (get-pox-rejection tx-sender vote-reward-cycle))
        (err ERR-STACKING-ALREADY-REJECTED))

    ;; tx-sender can't be a stacker
    (asserts! (is-none (get-stacker-info tx-sender))
        (err ERR-STACKING-ALREADY-STACKED))

    ;; tx-sender can't be a delegate
    (asserts! (is-none (get-delegate-control-info tx-sender))
        (err ERR-STACKING-DELEGATE-ALREADY-REGISTERED))

    ;; vote for rejection
    (map-set stacking-rejection
        { reward-cycle: vote-reward-cycle }
        { amount: (+ cur-rejected balance) }
    )

    ;; mark voted
    (map-set stacking-rejectors
        { stacker: tx-sender, reward-cycle: vote-reward-cycle }
        { amount: balance }
    )

    (ok true)))
)
