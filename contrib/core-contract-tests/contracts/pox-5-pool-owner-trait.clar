(define-trait pool-owner-trait (
  (validate-stake!
    ;; caller, amount-ustx, num-cycles, unlock-bytes
    (principal uint uint (buff 683))
    (response bool uint)
  )
  (validate-management!
    ;; caller, signer-key, pox-addr
    (principal (buff 33) {
      version: (buff 1),
      hashbytes: (buff 32),
    })
    (response bool uint)
  )
))
