;; The .exit-at-rc contract
;; Error codes
(define-constant ERR_AMOUNT_NOT_POSITIVE 2) ;; not testable
(define-constant ERR_PREVIOUS_VOTE_VALID 7) ;; g
(define-constant ERR_ALREADY_VETOED 9) ;; g
(define-constant ERR_UNAUTHORIZED_CALLER 10)  ;; g
(define-constant ERR_VOTER_NOT_STACKING 13) ;; wip
(define-constant ERR_BURN_BLOCK_HEIGHT_TOO_LOW 14)  ;; not testable
(define-constant ERR_FETCHING_BLOCK_INFO 16) ;; not testable
(define-constant ERR_NOT_ALLOWED 19)
(define-constant ERR_INVALID_PROPOSED_RC 21)  ;; g

;; Constants
(define-constant ABSOLUTE_MINIMUM_EXIT_RC u25)
(define-constant MAXIMUM_RC_BUFFER_FROM_PRESENT u25)
(define-constant MINIMUM_RC_BUFFER_FROM_PRESENT u6)

;; Data vars
(define-data-var pox-reward-cycle-length uint POX_REWARD_CYCLE_LENGTH)
(define-data-var first-burnchain-block-height uint FIRST_BURNCHAIN_BLOCK_HEIGHT)
(define-data-var configured bool false)

;; This function can only be called once, when it boots up
(define-public (set-burnchain-parameters (first-burn-height uint) (reward-cycle-length uint))
    (begin
        (asserts! (not (var-get configured)) (err ERR_NOT_ALLOWED))
        (var-set first-burnchain-block-height first-burn-height)
        (var-set pox-reward-cycle-length reward-cycle-length)
        (var-set configured true)
        (ok true))
)

(define-map rc-proposal-votes
    {
        proposed-rc: uint,
        curr-rc: uint
    }
    { votes: uint }
)

(define-map rc-proposal-vetoes
    {
        proposed-rc: uint,
        curr-rc: uint
    }
    { vetoes: uint }
)

(define-map exercised-veto
    {
        proposed-rc: uint,
        veto-height: uint
    }
    { vetoed: bool }
)

(define-map voter-state
    { address: principal }
    {
        proposed-rc: uint,
        amount: uint,
        expiration-reward-cycle: uint
    }
)

;; What's the reward cycle number of the burnchain block height?
;; Will runtime-abort if height is less than the first burnchain block (this is intentional)
;; Returns uint
(define-private (burn-height-to-reward-cycle (height uint))
    (let
        (
            (local-first-burnchain-block-height (var-get first-burnchain-block-height))
            (local-pox-reward-cycle-length (var-get pox-reward-cycle-length))
        )

        (asserts! (> height local-first-burnchain-block-height) (err ERR_BURN_BLOCK_HEIGHT_TOO_LOW))
        (asserts! (> local-pox-reward-cycle-length u0) (err ERR_AMOUNT_NOT_POSITIVE))

        (ok (/ (- height local-first-burnchain-block-height) local-pox-reward-cycle-length))
    )
)

;; What's the current PoX reward cycle?
;; Returns uint
(define-private (current-pox-reward-cycle)
    (burn-height-to-reward-cycle burn-block-height))


;; base cycle number for vote (some(15), some(16), some(17), none, none, none ...)
;; vote info (20 20 20 20 ...)
;; amount (10 10 10 ...)
(define-private (add-to-rc-proposal-map (cycle-opt (optional uint)) (proposed-rc uint) (amount uint))
    (begin
        (match cycle-opt
            cycle (match (map-get? rc-proposal-votes {proposed-rc: proposed-rc, curr-rc: cycle})
                              existing-votes (map-set rc-proposal-votes {proposed-rc: proposed-rc, curr-rc: cycle} {votes: (+ amount (get votes existing-votes)) })
                              ;; no existing state
                              (map-insert rc-proposal-votes {proposed-rc: proposed-rc, curr-rc: cycle} {votes: amount})
                          )
            false
        )
    )
)

(define-private (get-voting-reward-cycles (index uint) (lock-period uint) (first-reward-cycle uint))
    (begin
        (if (< index lock-period)
            (some (+ first-reward-cycle index))
            none
        )
    )
)

;; TODO - fill in boot code address for contract-call
(define-public (vote-for-exit-rc (proposed-exit-rc uint))
    (let (
        (stacker-info (unwrap! (contract-call? .pox get-stacker-info tx-sender) (err ERR_VOTER_NOT_STACKING)))
        (amount-stacked (get amount-ustx stacker-info))
        (stacking-expiration (+ (get lock-period stacker-info) (get first-reward-cycle stacker-info)))
        (current-reward-cycle (unwrap-panic (current-pox-reward-cycle)))
        (proposed-rc-list (list proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc proposed-exit-rc))
        (amount-stacked-list (list amount-stacked amount-stacked amount-stacked amount-stacked amount-stacked amount-stacked amount-stacked amount-stacked amount-stacked amount-stacked amount-stacked amount-stacked))
        (lock-period (get lock-period stacker-info))
        (lock-period-list (list lock-period lock-period lock-period lock-period lock-period lock-period lock-period lock-period lock-period lock-period lock-period lock-period))
        (first-reward-cycle (get first-reward-cycle stacker-info))
        (first-reward-cycle-list (list first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle first-reward-cycle))
        (list-indexes (list u0 u1 u2 u3 u4 u5 u6 u7 u8 u9 u10 u11))
        ;; a list of the reward cycles the voter's vote is valid for, corresponding to the cycles their stx is locked for
        (voting-reward-cycles (map get-voting-reward-cycles list-indexes lock-period-list first-reward-cycle-list ))
    )
        ;; Check that the amount stacked is positive
        (asserts! (> amount-stacked u0) (err ERR_AMOUNT_NOT_POSITIVE))

        ;; Check that the proposed exit rc is allowable
        (asserts! (>= proposed-exit-rc ABSOLUTE_MINIMUM_EXIT_RC) (err ERR_INVALID_PROPOSED_RC))
        (asserts! (>= proposed-exit-rc (+ current-reward-cycle MINIMUM_RC_BUFFER_FROM_PRESENT)) (err ERR_INVALID_PROPOSED_RC))
        (asserts! (<= proposed-exit-rc (+ current-reward-cycle MAXIMUM_RC_BUFFER_FROM_PRESENT)) (err ERR_INVALID_PROPOSED_RC))

        ;; Check that the voter does not have an outstanding vote for this rc
        (match (map-get? voter-state {address: tx-sender})
            voter-info (asserts! (>= current-reward-cycle (get expiration-reward-cycle voter-info))
                (err ERR_PREVIOUS_VOTE_VALID))
            ;; no existing state
            true
        )

        ;; Check that the caller is allowed
        (asserts! (is-eq tx-sender contract-caller) (err ERR_UNAUTHORIZED_CALLER))

        ;; Modify the voter-state map
        (map-set voter-state { address: tx-sender }
            { proposed-rc: proposed-exit-rc, amount: amount-stacked, expiration-reward-cycle: stacking-expiration })

        ;; Modify the rc-proposal-votes map - need to loop from curr rc to expiration rc
        (map add-to-rc-proposal-map voting-reward-cycles proposed-rc-list amount-stacked-list)

        (ok true)
    )
)

(define-public (veto-exit-rc (proposed-exit-rc uint))
    (let (
        (current-reward-cycle (unwrap-panic (current-pox-reward-cycle)))
        (curr-vetoes (default-to u0 (get vetoes (map-get? rc-proposal-vetoes { proposed-rc: proposed-exit-rc, curr-rc: current-reward-cycle } ))))
        (last-miner (unwrap! (get-block-info? miner-address (- block-height u1))
                    (err ERR_FETCHING_BLOCK_INFO)))
        (vetoed (default-to false (get vetoed (map-get? exercised-veto { proposed-rc: proposed-exit-rc, veto-height: block-height }))))
    )

    ;; a miner can only veto once per block
    (asserts! (not vetoed) (err ERR_ALREADY_VETOED))

    ;; a miner can only veto if they mined the previous block
    (asserts! (is-eq contract-caller last-miner) (err ERR_UNAUTHORIZED_CALLER))

    ;; modify state to store veto
    (map-set rc-proposal-vetoes { proposed-rc: proposed-exit-rc, curr-rc: current-reward-cycle } { vetoes: (+ u1 curr-vetoes) })
    (map-set exercised-veto { proposed-rc: proposed-exit-rc, veto-height: block-height }
                            { vetoed: true })

    (ok true)
    )
)