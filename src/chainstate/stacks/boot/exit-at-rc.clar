;; The .exit-at-rc contract
;; Error codes
(define-constant ERR_AMOUNT_NOT_POSITIVE 2)
(define-constant ERR_PREVIOUS_VOTE_VALID 7)
(define-constant ERR_ALREADY_VETOED 9)
(define-constant ERR_UNAUTHORIZED_CALLER 10)
(define-constant ERR_VOTER_NOT_STACKING 13)
(define-constant ERR_BURN_BLOCK_HEIGHT_TOO_LOW 14)
(define-constant ERR_FETCHING_BLOCK_INFO 16)
(define-constant ERR_NOT_ALLOWED 19)
(define-constant ERR_INVALID_PROPOSED_RC 21)

;; Constants
(define-constant ABSOLUTE_MINIMUM_EXIT_RC u33)
(define-constant MAXIMUM_RC_BUFFER_FROM_PRESENT u25)
(define-constant MINIMUM_RC_BUFFER_FROM_PRESENT u6)

;; Data vars
(define-data-var pox-reward-cycle-length uint POX_REWARD_CYCLE_LENGTH)
(define-data-var first-burnchain-block-height uint FIRST_BURNCHAIN_BLOCK_HEIGHT)
(define-data-var absolute-minimum-exit-rc uint ABSOLUTE_MINIMUM_EXIT_RC)
(define-data-var configured bool false)

;; This function can only be called once, when it boots up
(define-public (set-burnchain-parameters (first-burn-height uint) (reward-cycle-length uint) (min-exit-rc uint))
    (begin
        (asserts! (not (var-get configured)) (err ERR_NOT_ALLOWED))
        (var-set first-burnchain-block-height first-burn-height)
        (var-set pox-reward-cycle-length reward-cycle-length)
        (var-set absolute-minimum-exit-rc min-exit-rc)
        (var-set configured true)
        (ok true))
)

;; Stores number of votes for exit proposals by coupling it with the reward cycle the vote is cast in.
(define-map rc-proposal-votes
    {
        proposed-rc: uint,
        curr-rc: uint
    }
    { votes: uint }
)

;; Stores number of vetos for exit proposals by coupling it with the reward cycle the veto is cast in.
(define-map rc-proposal-vetoes
    {
        proposed-rc: uint,
        curr-rc: uint
    }
    { vetoes: uint }
)

;; Keeps track of miner vetos; used to ensure that a miner cannot cast multiple vetos in the same block.
(define-map exercised-veto
    {
        proposed-rc: uint,
        veto-height: uint
    }
    { vetoed: bool }
)

;; Keeps track of voter specific information; used to ensure a voter doesn't vote twice in the same stacking period.
(define-map voter-state
    principal
    {
        proposed-rc: uint,
        amount: uint,
        expiration-reward-cycle: uint
    }
)

;; What's the reward cycle number of the burnchain block height?
;; Returns uint
(define-private (burn-height-to-reward-cycle (height uint))
    (/ (- height (var-get first-burnchain-block-height)) (var-get pox-reward-cycle-length)))

;; What's the current PoX reward cycle?
;; Will runtime-abort if height is less than the first burnchain block (this is intentional).
;; Returns uint
(define-private (current-pox-reward-cycle)
    (let
        (
            (local-first-burnchain-block-height (var-get first-burnchain-block-height))
            (local-pox-reward-cycle-length (var-get pox-reward-cycle-length))
        )

        (asserts! (> burn-block-height local-first-burnchain-block-height) (err ERR_BURN_BLOCK_HEIGHT_TOO_LOW))
        (asserts! (> local-pox-reward-cycle-length u0) (err ERR_AMOUNT_NOT_POSITIVE))

        (ok (burn-height-to-reward-cycle burn-block-height))
    )
)


;; For a specific reward cycle, this function tried to add "amount" number of votes for the proposed exit reward cycle.
;; Note: votes are tied to reward cycles, since the vote's lifetime is tied to the voter's stacking duration.
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

;; Used to construct a list of the reward cycles that a voter's vote would be valid for (tied to their stacking duration).
;; Ex: if a user starts stacking at RC 18 for 3 cycles, the output of this function would be:
;;     [ (some 18), (some 19), (some 20), none, none, none, none, none, none, none, none, none ]
(define-private (get-voting-reward-cycles (index uint) (lock-period uint) (first-reward-cycle uint))
    (begin
        (if (< index lock-period)
            (some (+ first-reward-cycle index))
            none
        )
    )
)


(define-private (can-vote-for-exit-rc? (proposed-exit-rc uint))
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
        (asserts! (>= proposed-exit-rc (var-get absolute-minimum-exit-rc)) (err ERR_INVALID_PROPOSED_RC))
        (asserts! (>= proposed-exit-rc (+ current-reward-cycle MINIMUM_RC_BUFFER_FROM_PRESENT)) (err ERR_INVALID_PROPOSED_RC))
        (asserts! (<= proposed-exit-rc (+ current-reward-cycle MAXIMUM_RC_BUFFER_FROM_PRESENT)) (err ERR_INVALID_PROPOSED_RC))

        ;; Check that the voter does not have an outstanding vote for this reward cycle
        (match (map-get? voter-state tx-sender)
            voter-info (asserts! (>= current-reward-cycle (get expiration-reward-cycle voter-info))
                (err ERR_PREVIOUS_VOTE_VALID))
            ;; no existing state
            true
        )

        ;; Check that the caller is allowed
        (asserts! (is-eq tx-sender contract-caller) (err ERR_UNAUTHORIZED_CALLER))

        (ok { amount-stacked: amount-stacked, stacking-expiration: stacking-expiration, voting-reward-cycles: voting-reward-cycles, proposed-rc-list: proposed-rc-list, amount-stacked-list: amount-stacked-list })
    )
)


(define-private (inner-fulfill-vote (proposed-exit-rc uint) (voting-data {amount-stacked: uint, stacking-expiration: uint, voting-reward-cycles: (list 12 (optional uint)), proposed-rc-list: (list 12 uint), amount-stacked-list: (list 12 uint)}))
    (begin 
        ;; Modify the voter-state map
        (map-set voter-state tx-sender
            { proposed-rc: proposed-exit-rc, amount: (get amount-stacked voting-data), expiration-reward-cycle: (get stacking-expiration voting-data) })

        ;; Modify the rc-proposal-votes map - need to loop from curr rc to expiration rc
        (map add-to-rc-proposal-map (get voting-reward-cycles voting-data) (get proposed-rc-list voting-data) (get amount-stacked-list voting-data))

        (ok true)
    )
)

;; TODO (#3034) - fill in real address for contract-call once known
;; A stacking voter with no outstanding vote can call this function with their proposed exit reward cycle to vote for it.
;; This function enforces bounds on the vote (can't be above/below specific values).
;; If a vote is accepted, the voter can only re-vote when they stack again.
(define-public (vote-for-exit-rc (proposed-exit-rc uint))
    (let (
        (voting-data (try! (can-vote-for-exit-rc? proposed-exit-rc)))
    )
        (inner-fulfill-vote proposed-exit-rc voting-data)
    )
)


(define-private (can-veto-exit-rc? (proposed-exit-rc uint))
    (let (
        (current-reward-cycle (unwrap-panic (current-pox-reward-cycle)))
        (curr-vetoes (default-to u0 (get vetoes (map-get? rc-proposal-vetoes { proposed-rc: proposed-exit-rc, curr-rc: current-reward-cycle } ))))
        (last-miner (unwrap-panic (get-block-info? miner-address (- block-height u1))))
        (vetoed (default-to false (get vetoed (map-get? exercised-veto { proposed-rc: proposed-exit-rc, veto-height: block-height }))))
    )

    ;; a miner can only veto once per block
    (asserts! (not vetoed) (err ERR_ALREADY_VETOED))

    ;; a miner can only veto if they mined the previous block
    (asserts! (is-eq contract-caller last-miner) (err ERR_UNAUTHORIZED_CALLER))

    (ok {curr-rc: current-reward-cycle, curr-vetoes: curr-vetoes})
    )
)

(define-private (inner-fulfill-veto (proposed-exit-rc uint) (veto-data {curr-rc: uint, curr-vetoes: uint}))
    (begin
         ;; modify state to store veto
        (map-set rc-proposal-vetoes { proposed-rc: proposed-exit-rc, curr-rc: (get curr-rc veto-data) } { vetoes: (+ u1 (get curr-vetoes veto-data)) })
        (map-set exercised-veto { proposed-rc: proposed-exit-rc, veto-height: block-height }
                                { vetoed: true })

        (ok true)
    )
)

(define-public (veto-exit-rc (proposed-exit-rc uint))
    (let (
        (veto-data (try! (can-veto-exit-rc? proposed-exit-rc)))
    )
        (inner-fulfill-veto proposed-exit-rc veto-data)
    )
)

;; This function is used by miners to veto a proposed exit reward cycle. The veto period is active the reward cycle
;; after a vote is confirmed.
;; Note: a miner can send in a veto in the block after the one they mined, and they can't include multiple of these
;; transactions in a block.
(define-public (veto-exit-rc-old (proposed-exit-rc uint))
    (let (
        (current-reward-cycle (unwrap-panic (current-pox-reward-cycle)))
        (curr-vetoes (default-to u0 (get vetoes (map-get? rc-proposal-vetoes { proposed-rc: proposed-exit-rc, curr-rc: current-reward-cycle } ))))
        (last-miner (unwrap-panic (get-block-info? miner-address (- block-height u1))))
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