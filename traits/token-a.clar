(define-trait token-trait
  ((transfer? (principal principal uint) (response uint uint))
   ;; (meta-transfer? (<a> <a> uint) (response uint))
   (get-balance (principal) (response uint uint))))

(define-fungible-token token-a u1000000000)

(define-public (transfer? (amount uint) (recipient principal))
    (begin
        (ft-transfer? token-a amount tx-sender recipient)
        (ok amount)))

(define-public (get-balance (user principal))
    (ok (ft-get-balance token-a user)))

(begin
  (ft-mint? token-a u10000 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)
  (ft-mint? token-a u10000 'S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE)
  (ft-mint? token-a u10000 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
  (ft-mint? token-a u10000 'SPMQEKN07D1VHAB8XQV835E3PTY3QWZRZ5H0DM36))
