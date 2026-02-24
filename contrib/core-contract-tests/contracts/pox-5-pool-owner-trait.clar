(define-trait pool-owner-trait (
  ;; args:
  ;; (staker principal)
  ;; (amount-ustx uint)
  ;; (num-cycles uint)
  ;; (unlock-bytes (buff 255))
  (validate-stake! (principal uint uint (buff 255)) (response bool uint))

  ;; args:
  ;; (registering-tx-sender principal)
  ;; (signer-key (buff 33))
  ;; (pox-addr {
  ;;   version: (buff 1),
  ;;   hashbytes: (buff 32),
  ;; })
  (validate-registration! (principal (buff 33) {
    version: (buff 1),
    hashbytes: (buff 32),
  }) (response bool uint))
))
