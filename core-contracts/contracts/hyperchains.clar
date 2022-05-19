;; The .hyperchains contract

(define-constant CONTRACT_ADDRESS (as-contract tx-sender))

;; Error codes
(define-constant ERR_BLOCK_ALREADY_COMMITTED 1)
(define-constant ERR_INVALID_MINER 2)
(define-constant ERR_CONTRACT_CALL_FAILED 3)
(define-constant ERR_TRANSFER_FAILED 4)
(define-constant ERR_DISALLOWED_ASSET 5)
(define-constant ERR_ASSET_ALREADY_ALLOWED 6)
(define-constant ERR_MERKLE_ROOT_DOES_NOT_MATCH 7)
(define-constant ERR_INVALID_MERKLE_ROOT 8)
(define-constant ERR_WITHDRAWAL_ALREADY_PROCESSED 9)

;; Map from Stacks block height to block commit
(define-map block-commits uint (buff 32))
;; Map recording withdrawal roots
(define-map withdrawal-roots-map (buff 32) bool)
;; Map recording processed withdrawal leaves
(define-map processed-withdrawal-leaves-map (buff 32) bool)

;; List of miners
(define-constant miners (list 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY 'ST1AW6EKPGT61SQ9FNVDS17RKNWT8ZP582VF9HSCP 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5 'ST2GE6HSXT81X9X3ATQ14WPT49X915R8X7FVERMBP 'ST18F1AHKW194BWQ3CEFDPWVRARA79RBGFEWSDQR8))

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
(define-private (can-commit-block? (commit-block-height uint))
    (begin
        ;; check no block has been committed at this height
        (asserts! (is-none (map-get? block-commits commit-block-height)) (err ERR_BLOCK_ALREADY_COMMITTED))

        ;; check that the tx sender is one of the miners
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        (ok true)
    )
)

;; Helper function: modifies the block-commits map with a new commit and prints related info
;; TODO(60) store withdrawal-root in contract state
(define-private (inner-commit-block (block (buff 32)) (commit-block-height uint) (withdrawal-root (buff 32)))
    (begin
        (map-set block-commits commit-block-height block)
        (map-set withdrawal-roots-map withdrawal-root true)
        (print { event: "block-commit", block-commit: block, withdrawal-root: withdrawal-root})
        (ok block)
    )
)

;; Subnets miners call this to commit a block at a particular height
(define-public (commit-block (block (buff 32)) (withdrawal-root (buff 32)))
    (let ((commit-block-height block-height))
        (try! (can-commit-block? commit-block-height))
        (inner-commit-block block commit-block-height withdrawal-root)
    )
)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR NFT ASSET TRANSFERS

;; Helper function that transfers the specified NFT from the given sender to the given recipient. 
(define-private (inner-transfer-nft-asset (id uint) (sender principal) (recipient principal) (nft-contract <nft-trait>))
    (let (
            (call-result (contract-call? nft-contract transfer id sender recipient))
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
        (asserts! (try! (inner-transfer-nft-asset id sender CONTRACT_ADDRESS nft-contract)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event - the node consumes this
        (print { event: "deposit-nft", nft-id: id, l1-contract-id: nft-contract, hc-contract-id: hc-contract-id,
                 sender: sender, hc-function-name: hc-function-name })

        (ok true)
    )
)


;; Helper function for `withdraw-nft-asset`
(define-public (inner-withdraw-nft-asset (id uint) (recipient principal) (nft-contract <nft-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (let (
            (hashes-are-valid (check-withdrawal-hashes withdrawal-root withdrawal-leaf-hash sibling-hashes))
         )

        (asserts! (try! hashes-are-valid) (err ERR_MERKLE_ROOT_DOES_NOT_MATCH))

        ;; TODO: should check leaf validity

        (asserts! (try! (as-contract (inner-transfer-nft-asset id tx-sender recipient nft-contract))) (err ERR_TRANSFER_FAILED))

        (ok (finish-withdraw withdrawal-leaf-hash))
    )
)

;; A user calls this function to withdraw the specified NFT from this contract. 
;; In order for this withdrawal to go through, the given withdrawal must have been encoded 
;; in a withdrawal Merkle tree a hyperchain miner submitted. The user must provide the leaf 
;; hash of their withdrawal and the root hash of the specific Merkle tree their withdrawal 
;; is included in. They must also provide a list of sibling hashes. The withdraw function 
;; uses the provided hashes to ensure the requested withdrawal is valid. 
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (withdraw-nft-asset (id uint) (recipient principal) (nft-contract <nft-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (begin
        ;; Check that the asset belongs to the allowed-contracts map
        (unwrap! (map-get? allowed-contracts (contract-of nft-contract)) (err ERR_DISALLOWED_ASSET))
        
        (asserts! (try! (inner-withdraw-nft-asset id recipient nft-contract withdrawal-root withdrawal-leaf-hash sibling-hashes)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event - the node consumes this
        (print { event: "withdraw-nft", nft-id: id, l1-contract-id: nft-contract, recipient: recipient })

        (ok true)
    )
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR FUNGIBLE TOKEN ASSET TRANSFERS


(define-private (inner-transfer-ft-asset (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>))
    (let (
            (call-result (contract-call? ft-contract transfer amount sender recipient memo))
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
        (asserts! (try! (inner-transfer-ft-asset amount sender CONTRACT_ADDRESS memo ft-contract)) (err ERR_TRANSFER_FAILED))

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

;; This function performs validity checks related to the withdrawal and performs the withdrawal as well. 
(define-private (inner-withdraw-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (let (
            (hashes-are-valid (check-withdrawal-hashes withdrawal-root withdrawal-leaf-hash sibling-hashes))
         )

        (asserts! (try! hashes-are-valid) (err ERR_MERKLE_ROOT_DOES_NOT_MATCH))

        ;; TODO: should check leaf validity

        (asserts! (try! (as-contract (inner-transfer-ft-asset amount tx-sender recipient memo ft-contract))) (err ERR_TRANSFER_FAILED))

        (ok (finish-withdraw withdrawal-leaf-hash))
    )
)

;; A user can call this function to withdraw some amount of a fungible token asset from the 
;; contract and send it to a recipient. 
;; In order for this withdrawal to go through, the given withdrawal must have been encoded 
;; in a withdrawal Merkle tree a hyperchain miner submitted. The user must provide the leaf 
;; hash of their withdrawal and the root hash of the specific Merkle tree their withdrawal 
;; is included in. They must also provide a list of sibling hashes. The withdraw function 
;; uses the provided hashes to ensure the requested withdrawal is valid. 
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (withdraw-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (begin
        ;; Check that the asset belongs to the allowed-contracts map
        (unwrap! (map-get? allowed-contracts (contract-of ft-contract)) (err ERR_DISALLOWED_ASSET))

        (asserts! (try! (inner-withdraw-ft-asset amount recipient memo ft-contract withdrawal-root withdrawal-leaf-hash sibling-hashes)) (err ERR_TRANSFER_FAILED))

        (let (
                (ft-name (unwrap! (contract-call? ft-contract get-name) (err ERR_CONTRACT_CALL_FAILED)))
            )
            ;; Emit a print event - the node consumes this
            (print { event: "withdraw-ft", ft-amount: amount, l1-contract-id: ft-contract, recipient: recipient, ft-name: ft-name })
        )

        (ok true)
    )
)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR STX TRANSFERS


;; Helper function that transfers the given amount from the specified fungible token from the given sender to the given recipient. 
(define-private (inner-transfer-stx (amount uint) (sender principal) (recipient principal))
    (let (
            (call-result (stx-transfer? amount sender recipient))
            (transfer-result (unwrap! call-result (err ERR_TRANSFER_FAILED)))
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
        (asserts! (try! (inner-transfer-stx amount sender CONTRACT_ADDRESS)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event - the node consumes this
        (print { event: "deposit-stx", sender: sender, amount: amount })

        (ok true)
    )
)

;; A user calls this function to withdraw STX from this contract. 
;; In order for this withdrawal to go through, the given withdrawal must have been encoded 
;; in a withdrawal Merkle tree a hyperchain miner submitted. The user must provide the leaf 
;; hash of their withdrawal and the root hash of the specific Merkle tree their withdrawal 
;; is included in. They must also provide a list of sibling hashes. The withdraw function 
;; uses the provided hashes to ensure the requested withdrawal is valid. 
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (withdraw-stx (amount uint) (recipient principal) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (let (
            (hashes-are-valid (check-withdrawal-hashes withdrawal-root withdrawal-leaf-hash sibling-hashes))
         )

        (asserts! (try! hashes-are-valid) (err ERR_MERKLE_ROOT_DOES_NOT_MATCH))

        ;; TODO: should check leaf validity

        (asserts! (try! (as-contract (inner-transfer-stx amount tx-sender recipient))) (err ERR_TRANSFER_FAILED))

        (asserts! (finish-withdraw withdrawal-leaf-hash) (err ERR_WITHDRAWAL_ALREADY_PROCESSED))

        ;; Emit a print event - the node consumes this
        (print { event: "withdraw-stx", recipient: recipient, amount: amount })

        (ok true)
    )
)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; GENERAL WITHDRAWAL FUNCTIONS

;; This function concats the two given hashes in the correct order. It also prepends the buff `0x01`, which is 
;; a tag denoting a node (versus a leaf). 
(define-private (create-node-hash (curr-hash (buff 32)) (sibling-hash (buff 32)) (is-sibling-left-side bool))
    (let (
            (concatted-hash (if is-sibling-left-side
                    (concat sibling-hash curr-hash)
                    (concat curr-hash sibling-hash)
                ))
          )

          (concat 0x01 concatted-hash)
    )


)

;; This function hashes the curr hash with its sibling hash.
(define-private (hash-help (sibling (tuple (hash (buff 32)) (is-left-side bool))) (curr-node-hash (buff 32)))
    (let (
            (sibling-hash (get hash sibling))
            (is-sibling-left-side (get is-left-side sibling))
            (new-buff (create-node-hash curr-node-hash sibling-hash is-sibling-left-side))
        )
       (sha512/256 new-buff)
    )
)

;; This function checks:
;;  - That the provided withdrawal root matches a previously submitted one (passed to the function `commit-block`)
;;  - That the computed withdrawal root matches a previous valid withdrawal root 
;;  - That the given withdrawal leaf hash has not been previously processed
(define-private (check-withdrawal-hashes (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool)) )))
    (begin
        ;; Check that the user submitted a valid withdrawal root
        (asserts! (is-some (map-get? withdrawal-roots-map withdrawal-root)) (err ERR_INVALID_MERKLE_ROOT))

        ;; Check that this withdrawal leaf has not been processed before
        (asserts! (is-none (map-get? processed-withdrawal-leaves-map withdrawal-leaf-hash)) (err ERR_WITHDRAWAL_ALREADY_PROCESSED))

        (let (
                (calculated-withdrawal-root (fold hash-help sibling-hashes withdrawal-leaf-hash))
                (roots-match (is-eq calculated-withdrawal-root withdrawal-root))
            )
            (ok roots-match)
        )
    )
)

;; This function should be called after the asset in question has been transferred. 
;; It adds the withdrawal leaf hash to a map of processed leaves. This ensures that 
;; this withdrawal leaf can't be used again to withdraw additional funds. 
(define-private (finish-withdraw (withdrawal-leaf-hash (buff 32)))
    (map-insert processed-withdrawal-leaves-map withdrawal-leaf-hash true)
)