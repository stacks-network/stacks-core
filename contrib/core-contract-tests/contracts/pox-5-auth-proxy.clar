(use-trait signer-manager-trait 'ST000000000000000000002AMW42H.pox-5.signer-manager-trait)

(define-public (stake-for-sender
    (signer-manager <signer-manager-trait>)
    (amount-ustx uint)
    (num-cycles uint)
    (start-burn-ht uint)
    (signer-calldata (optional (buff 500)))
  )
  (contract-call? 'ST000000000000000000002AMW42H.pox-5 stake signer-manager
    amount-ustx num-cycles start-burn-ht signer-calldata
  )
)

(define-public (stake-update-for-sender
    (signer-manager <signer-manager-trait>)
    (old-signer-manager <signer-manager-trait>)
    (cycles-to-extend uint)
    (amount-increase uint)
    (signer-calldata (optional (buff 500)))
  )
  (contract-call? 'ST000000000000000000002AMW42H.pox-5 stake-update
    signer-manager old-signer-manager cycles-to-extend amount-increase
    signer-calldata
  )
)

(define-public (unstake-for-sender (old-signer-manager <signer-manager-trait>))
  (contract-call? 'ST000000000000000000002AMW42H.pox-5 unstake old-signer-manager)
)

(define-public (register-for-bond-for-sender
    (bond-index uint)
    (signer-manager <signer-manager-trait>)
    (amount-ustx uint)
    (btc-lockup (response {
      outputs: (list 10
        {
          height: uint,
          tx: (buff 100000),
          output-index: uint,
          header: (buff 80),
          leaf-hashes: (list 14 (buff 32)),
          tx-count: uint,
          tx-index: uint,
          amount: uint,
        }
      ),
      staker-unlock-bytes: (buff 683),
    }
      uint
    ))
    (signer-calldata (optional (buff 500)))
  )
  (contract-call? 'ST000000000000000000002AMW42H.pox-5 register-for-bond
    bond-index signer-manager amount-ustx btc-lockup signer-calldata
  )
)
