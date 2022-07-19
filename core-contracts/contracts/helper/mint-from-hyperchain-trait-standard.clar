(define-trait mint-from-hyperchain-trait
  (
    ;; Transfer from the sender to a new principal
    (mint-from-hyperchain (uint principal principal) (response bool uint))
  )
)