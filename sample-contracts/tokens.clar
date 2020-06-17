(define-map tokens ((account principal)) ((balance uint)))
(define-private (get-balance (account principal))
  (default-to 0u (get balance (map-get? tokens (tuple (account account))))))

(define-private (token-credit! (account principal) (amount uint))
  (if (<= amount 0u)
      (err "must move positive balance")
      (let ((current-amount (get-balance account)))
        (begin
          (map-set tokens (tuple (account account))
                      (tuple (balance (+ amount current-amount))))
          (ok amount)))))

(define-public (token-transfer (to principal) (amount uint))
  (let ((balance (get-balance tx-sender)))
    (if (or (> amount balance) (<= amount 0u))
        (err "must transfer positive balance and possess funds")
        (begin
          (map-set tokens (tuple (account tx-sender))
                      (tuple (balance (- balance amount))))
          (token-credit! to amount)))))

(define-public (mint! (amount uint))
   (let ((balance (get-balance tx-sender)))
     (token-credit! tx-sender amount)))

(token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10000u)
(token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 300u)
