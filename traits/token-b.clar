(impl-trait .fungible-token-trait)

(define-fungible-token token-b u1000000000)

(define-public (transfer? (amount uint) (recipient principal))
    (ft-transfer? token-b tx-sender recipient))

(define-public (get-balance (user principal))
    (ft-get-balance token-b user))

(begin
  (ft-mint? token-b u10000000000 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)
  (ft-mint? token-b u10000000 'S02J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKPVKG2CE)
  (ft-mint? token-b u10000000 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
  (ft-mint? token-b u10000000 'SPMQEKN07D1VHAB8XQV835E3PTY3QWZRZ5H0DM36))
