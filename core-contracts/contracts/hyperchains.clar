;; The .hyperchains contract

(define-constant CONTRACT_ADDRESS (as-contract tx-sender))

;; Error codes
(define-constant ERR_BLOCK_ALREADY_COMMITTED 1)
(define-constant ERR_INVALID_MINER 2)
(define-constant ERR_VALIDATION_FAILED 3)
(define-constant ERR_CONTRACT_CALL_FAILED 4)
(define-constant ERR_TRANSFER_FAILED 5)
(define-constant ERR_DISALLOWED_ASSET 6)
(define-constant ERR_ASSET_ALREADY_ALLOWED 7)

;; Map from Stacks block height to block commit
(define-map block-commits uint (buff 32))

;; List of miners
(define-constant miners (list 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY 'ST1AW6EKPGT61SQ9FNVDS17RKNWT8ZP582VF9HSCP 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5 'ST2GE6HSXT81X9X3ATQ14WPT49X915R8X7FVERMBP 'ST18F1AHKW194BWQ3CEFDPWVRARA79RBGFEWSDQR8))

;; Map of allowed contracts for asset transfers
(define-map allowed-contracts principal (string-ascii 45))

;; Testing info for 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5:
;;      secret_key: 7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801
;;      btc_address: mr1iPkD9N3RJZZxXRk7xF9d36gffa6exNC

;; Use trait declarations
(use-trait nft-trait .nft-trait-standard.nft-trait)
(use-trait ft-trait .ft-trait-standard.ft-trait)

;; This function adds contracts to the allowed-contracts map.
;; Once in this map, asset transfers from that contract will be allowed in the deposit and withdraw operations.
(define-public (setup-allowed-contracts)
    (begin
        ;; Verify that tx-sender is an authorized miner
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        (asserts! (map-insert allowed-contracts .simple-ft "hyperchain-deposit-ft-token") (err ERR_ASSET_ALREADY_ALLOWED))
        (asserts! (map-insert allowed-contracts .simple-nft "hyperchain-deposit-nft-token") (err ERR_ASSET_ALREADY_ALLOWED))

        (ok true)
    )
)

;; Helper function for fold: if a == b, return none; else return b
(define-private (is-principal-eq (miner-a principal) (search-for (optional principal)))
    (if (is-eq (some miner-a) search-for)
        none
        search-for
    )
)
;; Helper function: returns a boolean indicating whether the given principal is in the list of miners
(define-private (is-miner (miner principal))
   (let ((fold-result (fold is-principal-eq miners (some miner))))
        (is-none fold-result)
   ))

;; Helper function: determines whether the commit-block operation can be carried out
;; Fails if:
;;  1) we have already committed at this block height
;;  2) `target-block` is not the burn chain tip
;;  3) the sender is not a miner
(define-private (can-commit-block? (commit-block-height uint)  (target-block (buff 32)))
    (begin
        ;; check no block has been committed at this height
        (asserts! (is-none (map-get? block-commits commit-block-height)) (err ERR_BLOCK_ALREADY_COMMITTED))

        ;; check that `target-block` matches the burn chain tip
        (asserts! (is-eq 
            target-block 
            (unwrap! (get-block-info? id-header-hash (- block-height u1)) (err ERR_BLOCK_ALREADY_COMMITTED)) )
            (err ERR_BLOCK_ALREADY_COMMITTED)) 

        ;; check that the tx sender is one of the miners
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        (ok true)
    )
)

;; Helper function: modifies the block-commits map with a new commit and prints related info
(define-private (inner-commit-block (block (buff 32)) (commit-block-height uint))
    (begin
        (map-set block-commits commit-block-height block)
        (print { event: "block-commit", block-commit: block})
        (ok block)
    )
)

;; Subnets miners call this to commit a block at a particular height
(define-public (commit-block (block (buff 32)) (target-block (buff 32)))
    (let ((commit-block-height block-height))
        (unwrap! (can-commit-block? commit-block-height target-block) (err ERR_VALIDATION_FAILED))
        (inner-commit-block block commit-block-height)
    )
)

;; Returns the `id-header-hash` of the chain tip. This is used for `clarinet` tests
;; where we do not yet have access to this value through the API.
(define-read-only (get-id-header-hash)
    (ok (unwrap! (get-block-info? id-header-hash (- block-height u1)) (err ERR_VALIDATION_FAILED)))
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR NFT ASSET TRANSFERS


(define-private (inner-deposit-nft-asset (id uint) (sender principal) (nft-contract <nft-trait>))
    (let (
            (call-result (contract-call? nft-contract transfer id sender CONTRACT_ADDRESS))
            (transfer-result (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
        )
        ;; Check that the transfer succeeded
        (asserts! transfer-result (err ERR_TRANSFER_FAILED))

        (ok true)
    )
)

;; A user calls this function to deposit an NFT into the contract.
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (deposit-nft-asset (id uint) (sender principal) (nft-contract <nft-trait>) (hc-contract-id principal))
    (let (
            ;; Check that the asset belongs to the allowed-contracts map
            (hc-function-name (unwrap! (map-get? allowed-contracts (contract-of nft-contract)) (err ERR_DISALLOWED_ASSET)))
        )

        ;; Try to transfer the NFT to this contract
        (asserts! (unwrap! (inner-deposit-nft-asset id sender nft-contract) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event - the node consumes this
        (print { event: "deposit-nft", nft-id: id, l1-contract-id: nft-contract, hc-contract-id: hc-contract-id,
                 sender: sender, hc-function-name: hc-function-name })

        (ok true)
    )
)

;; Helper function for `withdraw-nft-asset`
(define-public (inner-withdraw-nft-asset (id uint) (recipient principal) (nft-contract <nft-trait>))
    (let (
        (call-result (as-contract (contract-call? nft-contract transfer id CONTRACT_ADDRESS recipient)))
        (transfer-result (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
    )
        ;; Check that the transfer succeeded
        (asserts! transfer-result (err ERR_TRANSFER_FAILED))

        (ok true)
    )
)

;; An authorized miner can call this function to withdraw an NFT asset from the contract and
;; send it to a recipient.
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (withdraw-nft-asset (id uint) (recipient principal) (nft-contract <nft-trait>) (hc-contract-id principal))
    (let (
            ;; Check that the asset belongs to the allowed-contracts map
            (hc-function-name (unwrap! (map-get? allowed-contracts (contract-of nft-contract)) (err ERR_DISALLOWED_ASSET)))
        )
        ;; Verify that tx-sender is an authorized miner
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        (asserts! (unwrap! (inner-withdraw-nft-asset id recipient nft-contract) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event - the node consumes this
        (print { event: "withdraw-nft", nft-id: id, l1-contract-id: nft-contract, hc-contract-id: hc-contract-id,
                recipient: recipient, hc-function-name: hc-function-name })

        (ok true)
    )
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR FUNGIBLE TOKEN ASSET TRANSFERS


(define-private (inner-deposit-ft-asset (amount uint) (sender principal) (memo (optional (buff 34))) (ft-contract <ft-trait>))
    (let (
            (call-result (contract-call? ft-contract transfer amount sender CONTRACT_ADDRESS memo))
            (transfer-result (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
        )
        ;; Check that the transfer succeeded
        (asserts! transfer-result (err ERR_TRANSFER_FAILED))

        (ok true)
    )
)

;; A user calls this function to deposit a fungible token into the contract.
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (deposit-ft-asset (amount uint) (sender principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (hc-contract-id principal))
    (let (
            ;; Check that the asset belongs to the allowed-contracts map
            (hc-function-name (unwrap! (map-get? allowed-contracts (contract-of ft-contract)) (err ERR_DISALLOWED_ASSET)))
        )
        ;; Try to transfer the FT to this contract
        (asserts! (unwrap! (inner-deposit-ft-asset amount sender memo ft-contract) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        (let (
                (ft-name (unwrap! (contract-call? ft-contract get-name) (err ERR_CONTRACT_CALL_FAILED)))
            )
            ;; Emit a print event - the node consumes this
            (print { event: "deposit-ft", ft-amount: amount, l1-contract-id: ft-contract,
                        ft-name: ft-name, hc-contract-id: hc-contract-id, sender: sender, hc-function-name: hc-function-name })
        )

        (ok true)
    )
)

;; Helper function for `withdraw-ft-asset`
(define-public (inner-withdraw-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>))
    (let (
        (call-result (as-contract (contract-call? ft-contract transfer amount CONTRACT_ADDRESS recipient memo)))
        (transfer-result (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
    )
        ;; Check that the transfer succeeded
        (asserts! transfer-result (err ERR_TRANSFER_FAILED))

        (ok true)
    )
)

;; An authorized miner can call this function to withdraw a fungible token asset from the contract and
;; send it to a recipient.
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (withdraw-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (hc-contract-id principal))
    (let (
            ;; Check that the asset belongs to the allowed-contracts map
            (hc-function-name (unwrap! (map-get? allowed-contracts (contract-of ft-contract)) (err ERR_DISALLOWED_ASSET)))
        )
        ;; Verify that tx-sender is an authorized miner
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        (asserts! (unwrap! (inner-withdraw-ft-asset amount recipient memo ft-contract) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        (let (
                (ft-name (unwrap! (contract-call? ft-contract get-name) (err ERR_CONTRACT_CALL_FAILED)))
            )
            ;; Emit a print event - the node consumes this
            (print { event: "withdraw-ft", ft-amount: amount, l1-contract-id: ft-contract, hc-contract-id: hc-contract-id,
                    recipient: recipient, ft-name: ft-name, hc-function-name: hc-function-name })
        )

        (ok true)
    )
)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR STX TRANSFERS


(define-private (inner-deposit-stx (amount uint) (sender principal))
    (let (
            (call-result (stx-transfer? amount sender CONTRACT_ADDRESS))
            (transfer-result (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
        )
        ;; Check that the transfer succeeded
        (asserts! transfer-result (err ERR_TRANSFER_FAILED))

        (ok true)
    )
)

;; A user calls this function to deposit STX into the contract.
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (deposit-stx (amount uint) (sender principal))
    (begin
        ;; Try to transfer the STX to this contract
        (asserts! (unwrap! (inner-deposit-stx amount sender) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event - the node consumes this
        (print { event: "deposit-stx", sender: sender, amount: amount })

        (ok true)
    )
)
