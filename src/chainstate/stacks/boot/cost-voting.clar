;; The .cost-voting contract

;; Error codes
(define-constant ERR_PROPOSE 1)

;; Cost vote token
(define-fungible-token cost-vote-token)

;; Proposal counter
(define-data-var proposal-counter uint 0)

;; Rollback proposal counter
(define-data-var rollback-proposal-counter uint 0)

;; cost-function proposals
(define-map proposals
    ((proposal-id uint))
    ((cost-function-contract principal)
     (cost-function-name (string-ascii 50))
     (function-contract principal)
     (function-name (string-ascii 50))
     (votes uint)
     (expiration-block-height uint)))

;; cost-function rollback proposals
(define-map rollback-proposals
    ((rollback-id uint))
    ((function-contract principal)
     (function-name (string-ascii 50))
     (votes uint)
     (expiration-block-height uint)))

;; Getter for cost-function proposals
(define-read-only (get-proposal (proposal-id uint))
    (map-get? proposals { proposal-id: proposal-id }))

;; Propose cost-functions
(define-public (submit-proposal (function-contract principal)
                                (function-name string-ascii)
                                (cost-function-contract principal)
                                (cost-function-name string-ascii))
    (begin
        (map-set proposals { proposal-id: (var-get proposal-counter) }
                           { cost-function-contract: cost-function-contract,
                             cost-function-name: cost-function-name,
                             function-contract: function-contract,
                             function-name: function-name,
                             votes: 0,
                             expiration-block-height: (+ burn-block-height 2016) })
        (var-set proposal-counter (+ (var-get proposal-counter) 1))
        (- (var-get proposal-counter) 1)))

;; Vote on a proposal
(define-public (vote (proposal-id uint) (amount uint))

)

;; Withdraw votes
(define-public (withdraw-vote (proposal-id uint) (amount uint))

)

;; Withdraw STX after vote is over
(define-public (withdraw-after-vote (proposal-id uint))

)

;; Miner veto
(define-public (veto (proposal-id uint))

)

;; Getter for cost-function rollback proposals
(define-read-only (get-rollback-proposal (rollback-id uint))
    (map-get? rollback-proposals { rollback-id: rollback-id }))

;; Propose cost-function rollback
(define-public (submit-rollback-proposal (function-name string-ascii) (function-contract principal))
    (begin
        (map-set proposal-rollbacks { rollback-id: (var-get rollback-proposal-counter) }
                                    { function-contract: function-contract,
                                      function-name: function-name,
                                      votes: 0,
                                      expiration-block-height: (+ burn-block-height 2016) })
        (var-set rollback-proposal-counter (+ (var-get rollback-proposal-counter) 1))
        (- (var-get rollback-proposal-counter) 1)))

;; Vote on a rollback proposal
(define-public (vote (rollback-id uint) (amount uint))

)

;; Withdraw rollback votes
(define-public (withdraw-rollback-vote (rollback-id uint) (amount uint))

)

;; Withdraw STX after rollback vote is over
(define-public (withdraw-after-rollback-vote (rollback-id uint))

)

;; Miner veto rollback proposal
(define-public (veto-rollback (rollback-id uint))

)
