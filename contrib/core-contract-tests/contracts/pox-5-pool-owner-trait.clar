(define-trait pool-owner-trait (
  (validate-stake!
    (principal uint uint (buff 683))
    (response bool uint)
  )
  (validate-registration!
    (principal (buff 33) {
      version: (buff 1),
      hashbytes: (buff 32),
    })
    (response bool uint)
  )
))
