(define-map tokens ((account principal)) ((balance int)))
(define (get-balance (account principal))
  (let ((balance
         (get balance (fetch-entry tokens (tuple (account account))))))
    (if (eq? balance 'null) 0 balance)))

(define (token-credit! (account principal) (tokens int))
  (if (<= tokens 0)
      'false
      (let ((current-amount (get-balance account)))
        (begin
          (set-entry! tokens (tuple (account account))
                      (tuple (balance (+ tokens current-amount))))
          'true))))
(define-public (token-transfer (to principal) (amount int))
  (let ((balance (get-balance tx-sender)))
    (if (or (> amount balance) (<= amount 0))
        'false
        (begin
          (set-entry! tokens (tuple (account tx-sender))
                      (tuple (balance (- balance amount))))
          (token-credit! to amount)))))

(define-public (mint! (amount int))
   (let ((balance (get-balance tx-sender)))
     (begin (set-entry! tokens (tuple (account tx-sender))
                        (tuple (balance (+ balance amount))))
            'true)))

(begin (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10000)
       (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 300)
       'null)
