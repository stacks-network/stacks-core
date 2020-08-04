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
(define-constant ERR-STACKING-ALREADY-WITHDRAWN 16)
(define-constant ERR-STACKING-DELEGATE-EXPIRED 17)

;; Min/max number of reward cycles uSTX can be locked for
(define-constant MIN-POX-REWARD-CYCLES u1)
(define-constant MAX-POX-REWARD-CYCLES u12)

;; Length of a reward cycle, in burnchain blocks.
;; This is registration window (250) + reward window (1000)
(define-constant REGISTRATION-WINDOW-LENGTH u250)
(define-constant REWARD-CYCLE-LENGTH u1250)

;; Valid values for burnchain address versions.
;; These correspond to address hash modes in Stacks 2.0.
(define-constant ADDRESS-VERSION-P2PKH u0)
(define-constant ADDRESS-VERSION-P2SH u1)
(define-constant ADDRESS-VERSION-P2WPKH u2)
(define-constant ADDRESS-VERSION-P2WSH u3)

;; Stacking thresholds
(define-constant STACKING-THRESHOLD-25 u20000)
(define-constant STACKING-THRESHOLD-100 u5000)

;; Data vars that store the registration window length 
;; and reward cycle length.  Implemented as data vars
;; in order to test more efficiently -- i.e. the test
;; framework can override with smaller values.
(define-data-var registration-window-length uint REGISTRATION-WINDOW-LENGTH)
(define-data-var reward-cycle-length uint REWARD-CYCLE-LENGTH)
(begin
    (if is-in-regtest
        (begin
            (var-set registration-window-length u2)
            (var-set reward-cycle-length u5)
            true
        )
        false
    )
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
        ;; who, if anyone, is the delegate for this account?
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
        ;; Start and end times for the delegate's tenure, in burnchain blocks.
        ;; The range is start-inclusive, end-exclusive.
        (burn-block-height-start uint)
        (burn-block-height-end uint)
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
        ;; Beginning of this delegate's tenure
        (first-reward-cycle uint)
        ;; How long the uSTX will be locked for
        (tenure uint)
        ;; Address to send the uSTX when they unlock, if the clients wants that,
        ;; and burn block height at which the delegate may withdraw.  This should
        ;; be set far enough in the future that the client has ample time to 
        ;; withdraw their uSTX on their own.
        (withdrawal (optional (tuple (recipient principal) (deadline uint))))
        ;; Whether or not the delegate has withdrawn the funds
        (withdrawn bool)
    )
)

;; The Stacking anchor-block rejections.  Stackers send these to _reject_
;; the miner-selected anchor block.  This is a PoX safety feature -- if miners
;; get greedy and start banding together to stack their own STX in order to
;; discount-mine, other Stackers can vote to shut down PoX for this reward cycle
;; and revert to PoB.  Rejections can only be sent during the reward cycle's
;; registration window.
;;
;; There are two ways this map can get updated:
;; * via a contract-call to the (stack-reject-pox) method, or
;; * via a transaction in the underlying burnchain that encodes the same data.
;; In the latter case, this map will be updated by the Stacks node itself,
;; and transactions in the burnchain will take priority over transactions
;; in the Stacks chain when processing this block.
;; NOTE: no deletions from this map!
(define-map stacking-rejections
    ((stacker principal))
    ((reward-cycle uint))
)

;; What's the reward cycle number, given the burnchain block height?
;; NOTE: the first-ever reward cycle number isn't 0.  This is deliberate.
(define-private (burn-height-to-reward-cycle (height uint)) (/ height (var-get reward-cycle-length)))
(define-private (reward-cycle-to-burn-height (cycle uint)) (* (var-get reward-cycle-length)))

;; What's the current reward cycle?
(define-read-only (get-current-reward-cycle) (burn-height-to-reward-cycle burn-block-height))

;; Is the given burn block height in a PoX registration window?
(define-read-only (is-burn-height-in-pox-registration-window (burn-height uint))
    (let (
        (reward-cycle-start-height (* (var-get reward-cycle-length) (/ burn-height (var-get reward-cycle-length))))
    )
    (and (>= burn-height reward-cycle-start-height)
         (< burn-height (+ reward-cycle-start-height (var-get registration-window-length))))
    )
)

;; Is the node _currently_ in a PoX registration window?
(define-read-only (is-pox-registration-window)
    (is-burn-height-in-pox-registration-window burn-block-height))

;; Get the id-block-hash of the given reward cycle's anchor block.
;; Returns (optional (buff 32))
;; * will be (some (..)) if this PoX fork has an anchor block in that cycle
;; * will be none if there was no anchor block confirmed, or no anchor block known
(define-read-only (get-reward-cycle-anchor-block (reward-cycle uint))
    ;; TODO: unstub
    ;; (get-block-info? pox-anchor-block (* reward-cycle (var-get reward-cycle-length)))
    (some 0x1111111111111111111111111111111111111111111111111111111111111111))

;; Get the _current_ PoX stacking principal information, with all the latest 
;; changes applied.  Do note that these changes may not be in effect for the
;; ongoing reward cycle.  To see the state of a principal in a given reward cycle,
;; Returns (optional stacking-state)
(define-read-only (get-current-stacker-info (stacker principal))
    (map-get? stacking-state { stacker: stacker }))

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

;; Is a PoX address registered in a given range of reward cycles?
;; Returns true if it's registered in at least one reward cycle in the given range.
;; Returns false if it's not registered in any reward cycle in the given range.
(define-private (is-pox-addr-registered (pox-addr (tuple (version uint) (hashbytes (buff 20))))
                                        (reward-cycle-start uint)
                                        (num-cycles uint))
    (let (
        (pox-addr-range-opt (map-get? pox-addr-reward-cycles { pox-addr: pox-addr }))
    )
    (begin
        (match pox-addr-range-opt
            ;; some range
            pox-addr-range
                (and (>= (+ reward-cycle-start num-cycles) (get first-reward-cycle pox-addr-range))
                     (< reward-cycle-start (+ (get first-reward-cycle pox-addr-range) (get num-cycles pox-addr-range))))
            ;; none
            false
        )
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
    (begin
        (map-set reward-cycle-pox-address-list
            { reward-cycle: reward-cycle, index: sz }
            { pox-addr: pox-addr, total-ustx: amount-ustx })
        (map-set reward-cycle-pox-address-list-len
            { reward-cycle: reward-cycle }
            { len: (+ u1 sz) })
        (+ u1 sz)
    ))
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
            (total-ustx
                (default-to
                    u0
                    (get total-ustx (map-get? reward-cycle-total-stacked { reward-cycle: reward-cycle }))))
        )
        (begin
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
            u1
        ))
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
    ;; For safety, add up the number of times (add-principal-to-ith-reward-cycle) returns 1.
    ;; It _should_ be equal to num-cycles.  The caller _should_ check this.
    (fold +
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
       u0)
)

;; What is the minimum number of uSTX to be stacked in the current reward cycle?
;; Used internally by the Stacks node, and visible publicly.
(define-read-only (get-stacking-minimum)
    (let (
        (ustx-stacked-so-far
            (default-to
                u0
                (get total-ustx (map-get? reward-cycle-total-stacked { reward-cycle: (get-current-reward-cycle) }))))
    )
    (begin
        (if (< ustx-stacked-so-far (/ total-liquid-ustx u4))
            ;; less than 25% of all liquid STX are stacked, so the threshold is smaller
            (/ total-liquid-ustx STACKING-THRESHOLD-25)
            ;; at least 25% of all liquid STX are stacked, so the threshold is larger
            (/ total-liquid-ustx STACKING-THRESHOLD-100))
    ))
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
                                           (num-cycles uint))
    (let (
        (ustx-min (get-stacking-minimum))
        (is-registered (is-pox-addr-registered pox-addr first-reward-cycle num-cycles))
    )
    (begin
        ;; can't be registered yet
        (asserts! (not is-registered)
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
        (add-pox-addr-to-reward-cycles pox-addr first-reward-cycle num-cycles amount-ustx)
        (ok true)
    ))
)

;; Is the given principal stacking in a given reward cycle?
(define-read-only (is-in-reward-set (stacker principal) (reward-cycle uint))
    (let (
        (reward-cycle-data
            (match (get-current-stacker-info stacker)
                data
                    { present: true, start: (get first-reward-cycle data), num-cycles: (get lock-period data) }
                { present: false, start: u0, num-cycles: u0 }))
    )
    (begin 
        (if (not (get present reward-cycle-data))
            false
            (and (>= reward-cycle (get start reward-cycle-data))
                 (< reward-cycle (+ (get start reward-cycle-data) (get num-cycles reward-cycle-data)))))
    ))
)

;; Is the given principal stacking in the current reward cycle?
(define-read-only (is-currently-stacking (stacker principal))
    (is-in-reward-set stacker (get-current-reward-cycle)))

;; Get the current PoX stacking principal information, but only if:
;; * the stacker exists,
;; * the stacker is stacking in the current reward cycle.
(define-read-only (get-current-stacker-info-checked (stacker principal))
    (begin 
        ;; must be in this reward set
        (asserts! (is-currently-stacking stacker)
            (err ERR-STACKING-EXPIRED))

        ;; must exist
        (match (get-current-stacker-info stacker)
            stacker-info
                (ok stacker-info)
            (err ERR-STACKING-NO-SUCH-PRINCIPAL))
    )
)

;; Get the a client stacker's delegate information.
;; Returns (optional principal) -- will be (some ..) if a delegate is registered for the
;; given stacker at the given burn block height, or none if not.
(define-read-only (get-client-delegate-info (client-stacker principal))
    (map-get? delegates { stacker: client-stacker })
)

;;; Get the delegate control info
(define-read-only (get-delegate-control-info (delegate principal))
    (map-get? delegate-control { delegate: delegate }))

;; Delegate registration.
;; A delegate must register itself and a PoX address before
;; other Stackers can delegate to it.  It also registers the duration
;; for which its clients' uSTX will be locked.
(define-public (register-delegate (delegate principal)
                                  (pox-addr (tuple (version uint) (hashbytes (buff 20))))
                                  (tenure-burn-block-begin uint)
                                  (tenure-reward-cycles uint)
                                  (withdrawal (optional (tuple (recipient principal) (deadline uint)))))
    (begin
        ;; must not be a registered delegate already
        (asserts! (is-none (get-delegate-control-info delegate))
            (err ERR-STACKING-DELEGATE-ALREADY-REGISTERED))

        ;; lock period must be in acceptable range.
        (asserts! (check-pox-lock-period tenure-reward-cycles)
            (err ERR-STACKING-INVALID-DELEGATE-TENURE))

        ;; PoX address version must be valid
        (asserts! (check-pox-addr-version (get version pox-addr))
            (err ERR-STACKING-INVALID-POX-ADDRESS))

        ;; tenure start height must be in the next reward cycle or later
        (asserts! (< (get-current-reward-cycle) (burn-height-to-reward-cycle tenure-burn-block-begin))
            (err ERR-STACKING-INVALID-LOCK-PERIOD))

        ;; register!
        (map-set delegate-control
            { delegate: delegate }
            {
                total-ustx: u0,
                pox-addr: pox-addr,
                first-reward-cycle: (burn-height-to-reward-cycle tenure-burn-block-begin),
                tenure: tenure-reward-cycles,
                withdrawal: withdrawal,
                withdrawn: false
            }
        )
        (ok true)
    )
)

;; Delegated uSTX lock-up.
;; The Stacker (the caller) locks up their uSTX, and specifies a delegate
;; configuration to use.  The delegate will then carry out the PoX address
;; registration and withdrawal on their behalf.
;; Some checks are performed:
;; * the Stacker must not currently be Stacking.  Withdraw your tokens before calling this.
;; * The Stacker must have the given amount-ustx funds available.
;; * The Stacker cannot be a delegate
;; * The stacker cannot have a delegate
;; * The delegate's tenure must not have started
;; * The delegate must have not have begun.
;; The Stacker can withdraw their uSTX once the Stacking period stops.
(define-public (delegate-stx (delegate principal)
                             (amount-ustx uint))
    (let (
        (this-contract (as-contract tx-sender))
        
        ;; this stacker's first reward cycle is the _next_ reward cycle
        (first-reward-cycle (+ u1 (get-current-reward-cycle)))

        ;; existing delegate control record -- the delegate must
        ;; have registered itself.
        (delegate-control-info
           (unwrap!
               (get-delegate-control-info delegate)
               (err ERR-STACKING-NO-SUCH-DELEGATE)))
    )
    (begin 
        ;; tx-sender principal (the Stacker) must not be Stacking.
        ;; If you get this error, and your uSTX are expired, you'll need to withdraw
        ;; them first.
        (asserts! (is-none (get-current-stacker-info tx-sender))
            (err ERR-STACKING-ALREADY-STACKED))
        
        ;; the Stacker must have no delegate/client relationships
        (asserts! (is-none (get-client-delegate-info tx-sender))
            (err ERR-STACKING-ALREADY-DELEGATED))

        ;; the Stacker must not be registered as a delegate
        (asserts! (is-none (get-delegate-control-info tx-sender))
            (err ERR-STACKING-BAD-DELEGATE))

        ;; the delegate must not have begun stacking yet
        (asserts! (is-none (get-current-stacker-info delegate))
            (err ERR-STACKING-ALREADY-DELEGATED))

        ;; the delegate's tenure must not have started yet
        (asserts! (< (get first-reward-cycle delegate-control-info) (get-current-reward-cycle))
            (err ERR-STACKING-DELEGATE-EXPIRED))

        ;; lock up the uSTX in this contract
        (unwrap!
            (stx-transfer? amount-ustx tx-sender this-contract)
            (err ERR-STACKING-INSUFFICIENT-FUNDS))

        ;; encode the delegate/client relationship
        (map-set delegates
            { stacker: tx-sender }
            {
                delegate: delegate,
                amount-ustx: amount-ustx,
                burn-block-height-start: (reward-cycle-to-burn-height first-reward-cycle),
                burn-block-height-end: (reward-cycle-to-burn-height (+ first-reward-cycle (get tenure delegate-control-info))),
            }
        )

        ;; update how much uSTX the delegate now controls in total
        (map-set delegate-control
            { delegate: delegate }
            {
                total-ustx: (+ amount-ustx (get total-ustx delegate-control-info)),
                pox-addr: (get pox-addr delegate-control-info),
                first-reward-cycle: (get first-reward-cycle delegate-control-info),
                tenure: (get tenure delegate-control-info),
                withdrawal: (get withdrawal delegate-control-info),
                withdrawn: (get withdrawn delegate-control-info)
            }
        )

        ;; add a stacker record for this principal
        (map-set stacking-state
            { stacker: tx-sender }
            {
                amount-ustx: amount-ustx,
                pox-addr: (get pox-addr delegate-control-info),
                first-reward-cycle: first-reward-cycle,
                lock-period: (get tenure delegate-control-info),
                delegate: (some delegate)
            }
        )

        ;; we're done! let the delgate do its thing
        (ok true)
    ))
)

;; Lock up some uSTX for stacking!  Note that the given amount here is in micro-STX (uSTX).
;; The STX will be locked for the given number of reward cycles (lock-period).
;; This is the self-service interface.  tx-sender will be the Stacker.
;;
;; * The given stacker cannot currently be stacking, or have been stacking in the past without
;; first withdrawing.
;; * You will need the minimum uSTX threshold.  This will be determined by (get-stacking-minimum)
;; at the time this method is called.
;; * You may need to increase the amount of uSTX locked up later, since the minimum uSTX threshold
;; may increase between reward cycles.
(define-public (stack-stx (amount-ustx uint)
                          (pox-addr (tuple (version uint) (hashbytes (buff 20))))
                          (lock-period uint))
    (let (
        (this-contract (as-contract tx-sender))
        
        ;; this stacker's first reward cycle is the _next_ reward cycle
        (first-reward-cycle (+ u1 (get-current-reward-cycle)))
    )
    (begin
        ;; tx-sender principal must not be registered -- not now, and not in the past.
        ;; If you get this error, and your uSTX are expired, you'll need to withdraw
        ;; them first.
        (asserts! (is-none (get-current-stacker-info tx-sender))
            (err ERR-STACKING-ALREADY-STACKED))

        ;; tx-sender must not have a delegate/client relationsion
        (asserts! (is-none (get-client-delegate-info tx-sender))
            (err ERR-STACKING-ALREADY-DELEGATED))

        ;; tx-sender must not be a delegate
        (asserts! (is-none (get-delegate-control-info tx-sender))
            (err ERR-STACKING-BAD-DELEGATE))

        ;; lock up the uSTX in this contract
        (unwrap!
            (stx-transfer? amount-ustx tx-sender this-contract)
            (err ERR-STACKING-INSUFFICIENT-FUNDS))
        
        ;; register the PoX address with the amount stacked
        (try!
            (register-pox-addr-checked pox-addr amount-ustx first-reward-cycle lock-period))

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

        (ok true)
    ))
)

;; Delegated uSTX lockup, executed by the delegate.
;; The stacker will be the delegate, in place of its clients' uSTX.
;; The delegate can only call this once per stacking tenure.
;; Once called, no future Stackers can add this delegate as their delegate.
(define-public (delegate-stack-stx)
    (let (
        ;; delegate must exist
        (delegate-control-info 
            (unwrap!
                (get-delegate-control-info tx-sender)
                (err ERR-STACKING-NO-SUCH-DELEGATE)))

        ;; this stacker's first reward cycle is the _next_ reward cycle
        (first-reward-cycle (+ u1 (get-current-reward-cycle)))
    )
    (begin
        ;; tx-sender principal is the delegate, and it must not yet be stacking
        (asserts! (is-none (get-current-stacker-info tx-sender))
            (err ERR-STACKING-ALREADY-STACKED))

        ;; delegate's tenure must not have begun yet
        (asserts! (< (get first-reward-cycle delegate-control-info) (get-current-reward-cycle))
            (err ERR-STACKING-DELEGATE-EXPIRED))

        ;; register the PoX address with the amount stacked
        (try!
            (register-pox-addr-checked
                (get pox-addr delegate-control-info)
                (get total-ustx delegate-control-info)
                first-reward-cycle
                (get tenure delegate-control-info)))

        ;; add stacker record for the delegate
        (map-set stacking-state
            { stacker: tx-sender }
            {
                amount-ustx: (get total-ustx delegate-control-info),
                pox-addr: (get pox-addr delegate-control-info),
                first-reward-cycle: first-reward-cycle,
                lock-period: (get tenure delegate-control-info),
                delegate: none
            }
        )

        (ok true)
    ))
)

;; Update the delegate control record to indicate that a client
;; who delegated their funds to a delegate has withdrawn them.
;; The client is tx-sender.
;; 
;; * If the client (tx-sender) has no delegate, then do nothing.
;; * If the client has a delegate, and the delegate has not withdrawn the funds already, then deduct
;; the delegate's total-ustx and clear the delegate/client relationship.
;; * If the client's delegate has already withdrawn the funds, then error out.
;; 
;; Returns (ok ..) if the withdrawal can proceed
;; Returns (err ..) if the withdrawal cannot proceed, and indicates why in the error code.
(define-private (update-total-ustx-delegated)
    (let (
        (stacker-info
            (unwrap!
                (get-current-stacker-info tx-sender)
                (err ERR-STACKING-NO-SUCH-PRINCIPAL)))
    )
    ;; If tx-sender has a delegate, then deduct the uSTX it controls from its total amount.
    ;; Otherwise, do nothing.
    (match (get delegate stacker-info)
        delegate
            ;; have delegate!  Deduct total uSTX controlled by the delegate.
            (begin
                ;; Must have delegate-control-info for this delegate, so go get it.
                (try!
                    (match (get-delegate-control-info delegate)
                        ;; Have delegate control info for delegate!
                        delegate-control-info
                            (if (not (get withdrawn delegate-control-info))
                                ;; Delegate has not withdrawn tokens yet (if ever).
                                ;; So, we can proceed to do it ourselves.  Update the records.
                                (begin
                                    ;; Delegate control info should indicate that we have enough uSTX locked to process the withdrawal.
                                    (asserts! (>= (get total-ustx delegate-control-info) (get amount-ustx stacker-info))
                                        (err ERR-STACKING-UNREACHABLE))

                                    ;; Deduct from deletate's control record's total.
                                    (map-set delegate-control
                                        { delegate: delegate }
                                        {
                                            total-ustx: (- (get total-ustx delegate-control-info) (get amount-ustx stacker-info)),
                                            pox-addr: (get pox-addr delegate-control-info),
                                            first-reward-cycle: (get first-reward-cycle delegate-control-info),
                                            tenure: (get tenure delegate-control-info),
                                            withdrawal: (get withdrawal delegate-control-info),
                                            withdrawn: (get withdrawn delegate-control-info)
                                        }
                                    )

                                    (ok true)
                                )
                                ;; Otherwise, the withdrawal can't happen -- the delegate already did this.
                                (err ERR-STACKING-ALREADY-WITHDRAWN)
                            )
                        ;; have delegate but no delegate-control-info. should never happen!
                        (err ERR-STACKING-UNREACHABLE)
                    )
                )
                ;; Clear the delegate/client relationship for this client.
                (map-delete delegates { stacker: tx-sender })
                (ok true)
            )
        ;; No delegate, so nothing to do.
        (ok true)
    ))
)

;; Withdraw uSTX that are no longer locked up.
;; Send them to the given recipient.
;; This is a self-service interface -- STX owners call this directly.
;; Returns (ok true) if the withdrawal went through.
;; Returns (ok false) if the stacker had a delegate that already withdrew the funds.
;; Returns (err ..) in other irrecoverable cases
(define-public (withdraw-stx (recipient principal))
    (let (
        (this-contract (as-contract tx-sender))

        ;; tx-sender must have been stacking
        (stacker-info
            (unwrap!
                (get-current-stacker-info tx-sender)
                (err ERR-STACKING-NO-SUCH-PRINCIPAL)))
    )
    (begin
        ;; lock period must have passed
        (asserts! (> (get-current-reward-cycle) (+ (get first-reward-cycle stacker-info) (get lock-period stacker-info)))
            (err ERR-STACKING-STX-LOCKED))

        ;; tx-sender cannot be a delegate
        (asserts! (is-none (get-delegate-control-info tx-sender))
            (err ERR-STACKING-BAD-DELEGATE))

        ;; if tx-sender has a delegate, then deduct the uSTX it controls from its total amount.
        (match (update-total-ustx-delegated)
            ok-case
                (begin
                    ;; clear stacking state
                    (map-delete stacking-state { stacker: tx-sender })

                    ;; withdraw funds
                    (unwrap!
                        (stx-transfer? (get amount-ustx stacker-info) this-contract recipient)
                        (err ERR-STACKING-UNREACHABLE))

                    (ok ok-case)
                )
            err-case
                (if (is-eq err-case ERR-STACKING-ALREADY-WITHDRAWN)
                    ;; Stacker had a delegate that already withdrew the tokens.
                    ;; Just clear out the state.  No withdrawal will happen.
                    (begin
                        (map-delete delegates { stacker: tx-sender })
                        (map-delete stacking-state { stacker: tx-sender })
                        (ok false)
                    )
                    ;; Some other error
                    (err err-case)
                )
        )
    ))
)

;; Delegated-withdraw uSTX that are no longer locked up.
;; Send them to the recipient in the delegator's control record.
;; This is called by the delegate, and only works if there
;; is a withdraw recipient set.
;; It cannot be called more than once.
(define-public (delegate-withdraw-stx)
    (let (
        (this-contract (as-contract tx-sender))

        ;; tx-sender (the delegate) must have a stacking record
        (stacker-info
            (unwrap!
                (get-current-stacker-info tx-sender)
                (err ERR-STACKING-NO-SUCH-PRINCIPAL)))

        ;; tx-sender (the delegate) must be a registered delegate
        (delegate-control-info
            (unwrap!
                (get-delegate-control-info tx-sender)
                (err ERR-STACKING-NO-SUCH-DELEGATE)))
    )
    (begin
        ;; lock period must have passed
        (asserts! (> (get-current-reward-cycle) (+ (get first-reward-cycle stacker-info) (get lock-period stacker-info)))
            (err ERR-STACKING-STX-LOCKED))
        
        ;; tx-sender (the delegate) cannot have set a delegate (should never happen)
        (asserts! (is-none (get delegate stacker-info))
            (err ERR-STACKING-UNREACHABLE))

        ;; tokens must not have been withdrawn by the delegate yet
        (asserts! (not (get withdrawn delegate-control-info))
            (err ERR-STACKING-ALREADY-WITHDRAWN))

        ;; tx-sender (the delegate) must have permission to withdraw
        (let (
            (withdrawal
                (unwrap!
                    (get withdrawal delegate-control-info)
                    (err ERR-STACKING-PERMISSION-DENIED)))
        )
        (begin
            ;; withdrawl burn block deadline must have passed
            (asserts! (< burn-block-height (get deadline withdrawal))
                (err ERR-STACKING-PERMISSION-DENIED))

            ;; withdraw all remaining uSTX to the given recipient
            (unwrap!
                (stx-transfer? (get total-ustx delegate-control-info) this-contract (get recipient withdrawal))
                (err ERR-STACKING-UNREACHABLE))

            ;; clear total-ustx and mark withdrawn
            (map-set delegate-control
                { delegate: tx-sender }
                {
                    total-ustx: u0,
                    pox-addr: (get pox-addr delegate-control-info),
                    first-reward-cycle: (get first-reward-cycle delegate-control-info),
                    tenure: (get tenure delegate-control-info),
                    withdrawal: (get withdrawal delegate-control-info),
                    withdrawn: true
                }
            )

            ;; clear stacking state for the delegate
            (map-delete stacking-state { stacker: tx-sender })
        ))

        (ok true)
    ))
)

