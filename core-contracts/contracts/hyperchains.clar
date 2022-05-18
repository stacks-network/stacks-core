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
(define-constant ERR_MERKLE_ROOT_DOES_NOT_MATCH 8)
(define-constant ERR_INVALID_MERKLE_ROOT 9)
(define-constant ERR_WITHDRAWAL_ALREADY_PROCESSED 10)

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
        (unwrap! (can-commit-block? commit-block-height) (err ERR_VALIDATION_FAILED))
        (inner-commit-block block commit-block-height withdrawal-root)
    )
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
        (asserts! (unwrap! (inner-transfer-ft-asset amount sender CONTRACT_ADDRESS memo ft-contract) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

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


(define-private (inner-withdraw-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (withdrawal-root (buff 32)) (claim-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (let (
            (roots-match (check-withdrawal-root withdrawal-root claim-hash sibling-hashes))
         )

        (asserts! (unwrap! roots-match (err ERR_MERKLE_ROOT_DOES_NOT_MATCH)) (err ERR_MERKLE_ROOT_DOES_NOT_MATCH))

        ;; TODO: should check leaf validity

        (asserts! (unwrap! (as-contract (inner-transfer-ft-asset amount tx-sender recipient memo ft-contract)) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        (finish-withdraw claim-hash)
    )
)

;; An authorized miner can call this function to withdraw a fungible token asset from the contract and
;; send it to a recipient.
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (withdraw-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (withdrawal-root (buff 32)) (claim-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (begin
        ;; Check that the asset belongs to the allowed-contracts map
        (unwrap! (map-get? allowed-contracts (contract-of ft-contract)) (err ERR_DISALLOWED_ASSET))
        ;; Verify that tx-sender is an authorized miner
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        (asserts! (unwrap! (inner-withdraw-ft-asset amount recipient memo ft-contract withdrawal-root claim-hash sibling-hashes) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        (let (
                (ft-name (unwrap! (contract-call? ft-contract get-name) (err ERR_CONTRACT_CALL_FAILED)))
            )
            ;; Emit a print event - the node consumes this
            (print { event: "withdraw-ft", ft-amount: amount, l1-contract-id: ft-contract,
                    recipient: recipient, ft-name: ft-name })
        )

        (ok true)
    )
)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR STX TRANSFERS


(define-private (inner-transfer-stx (amount uint) (sender principal) (recipient principal))
    (let (
            (call-result (stx-transfer? amount sender recipient))
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
        (asserts! (unwrap! (inner-transfer-stx amount sender CONTRACT_ADDRESS) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event - the node consumes this
        (print { event: "deposit-stx", sender: sender, amount: amount })

        (ok true)
    )
)



(define-public (withdraw-stx (amount uint) (recipient principal) (withdrawal-root (buff 32)) (claim-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (let (
            (roots-match (check-withdrawal-root withdrawal-root claim-hash sibling-hashes))
         )

        (asserts! (unwrap! roots-match (err ERR_MERKLE_ROOT_DOES_NOT_MATCH)) (err ERR_MERKLE_ROOT_DOES_NOT_MATCH))

        (asserts! (unwrap! (as-contract (inner-transfer-stx amount tx-sender recipient)) (err ERR_TRANSFER_FAILED)) (err ERR_TRANSFER_FAILED))

        (ok true)
    )
)



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; GENERAL WITHDRAWAL FUNCTIONS


(define-private (create-new-buff (curr-hash (buff 32)) (sibling-hash (buff 32)) (is-sibling-left-side bool))
    (let (
            (concatted-hash (if is-sibling-left-side
                    (concat sibling-hash curr-hash)
                    (concat curr-hash sibling-hash)
                ))
          )

          (concat 0x01 concatted-hash)
    )


)

(define-private (hash-help (sibling (tuple (hash (buff 32)) (is-left-side bool))) (curr-node-hash (buff 32)))
    (let (
            (sibling-hash (get hash sibling))
            (is-sibling-left-side (get is-left-side sibling))
            (new-buff (create-new-buff curr-node-hash sibling-hash is-sibling-left-side))
        )
       (sha512/256 new-buff)
    )
)

;; might need to pass in list describing left or right sibling - this affects concatenation order in hash-help
(define-private (check-withdrawal-root (withdrawal-root (buff 32)) (claim-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool)) )))
    (begin
        ;; Check that the user submitted a valid withdrawal root
        (asserts! (is-some (map-get? withdrawal-roots-map withdrawal-root)) (err ERR_INVALID_MERKLE_ROOT))

        ;; Check that this withdrawal leaf has not been processed before
        (asserts! (is-none (map-get? processed-withdrawal-leaves-map claim-hash)) (err ERR_WITHDRAWAL_ALREADY_PROCESSED))

        (let (
                (calculated-withdrawal-root (fold hash-help sibling-hashes claim-hash))
                (roots-match (is-eq calculated-withdrawal-root withdrawal-root))
            )
            (print { calculated-root: calculated-withdrawal-root, roots-match: roots-match, sibs: sibling-hashes, claim-hash: claim-hash, actual-root: withdrawal-root })
            (ok roots-match)
        )
    )
)

(define-private (finish-withdraw (claim-hash (buff 32)))
    (begin
        (asserts! (map-insert processed-withdrawal-leaves-map claim-hash true) (err ERR_WITHDRAWAL_ALREADY_PROCESSED))
        (ok true)
    )
)