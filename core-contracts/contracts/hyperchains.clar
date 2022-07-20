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
(define-constant ERR_VALIDATION_FAILED 10)
;;; The value supplied for `target-chain-tip` does not match the current chain tip.
(define-constant ERR_INVALID_CHAIN_TIP 11)
;;; The contract was called before reaching this-chain height reaches 1.
(define-constant ERR_CALLED_TOO_EARLY 12)
(define-constant ERR_MINT_FAILED 13)
(define-constant ERR_ATTEMPT_TO_TRANSFER_ZERO_AMOUNT 14)
(define-constant ERR_IN_COMPUTATION 15)
;; The contract does not own this NFT to withdraw it.
(define-constant ERR_NFT_NOT_OWNED_BY_CONTRACT 16)
=======
(define-constant ERR_MINER_ALREADY_SET 20)

;; Map from Stacks block height to block commit
(define-map block-commits uint (buff 32))
;; Map recording withdrawal roots
(define-map withdrawal-roots-map (buff 32) bool)
;; Map recording processed withdrawal leaves
(define-map processed-withdrawal-leaves-map { withdrawal-leaf-hash: (buff 32), withdrawal-root-hash: (buff 32) } bool)

;; List of miners
(define-data-var miner (optional principal) none)

;; Map of allowed contracts for asset transfers - maps contract principal to name of the deposit function in the given contract
(define-map allowed-contracts principal (string-ascii 45))

;; Testing info for 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5:
;;      secret_key: 7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801
;;      btc_address: mr1iPkD9N3RJZZxXRk7xF9d36gffa6exNC

;; Use trait declarations
(use-trait nft-trait .trait-standards.nft-trait)
(use-trait ft-trait .trait-standards.ft-trait)
(use-trait mint-from-hyperchain-trait .trait-standards.mint-from-hyperchain-trait)

;; Set the hc miner for this contract. Can be called by *anyone*
;;  before the miner is set. This is an unsafe way to initialize the
;;  contract, because a re-org could allow someone to reinitialize
;;  this field. Instead, authors should initialize the variable
;;  directly at the data-var instantiation. This is used for testing
;;  purposes only. 
(define-public (set-hc-miner (miner-to-set principal))
    (match (var-get miner) existing-miner (err ERR_MINER_ALREADY_SET) 
        (begin 
            (var-set miner (some miner-to-set))
            (ok true))))

;; This function adds contracts to the allowed-contracts map.
;; Once in this map, asset transfers from that contract will be allowed in the deposit and withdraw operations.
;; Returns response<bool, int>
(define-public (setup-allowed-contracts)
    (begin
        ;; Verify that tx-sender is an authorized miner
        (asserts! (or (is-eq tx-sender CONTRACT_ADDRESS)
                      (is-miner tx-sender))
                  (err ERR_INVALID_MINER))

        ;; Set up the assets that the contract is allowed to transfer
        (asserts! (map-insert allowed-contracts .simple-ft "hyperchain-deposit-ft-token") (err ERR_ASSET_ALREADY_ALLOWED))
        (asserts! (map-insert allowed-contracts .simple-nft "hyperchain-deposit-nft-token") (err ERR_ASSET_ALREADY_ALLOWED))
        (asserts! (map-insert allowed-contracts .simple-nft-no-mint "hyperchain-deposit-nft-token-no-mint") (err ERR_ASSET_ALREADY_ALLOWED))

        (ok true)
    )
)

(define-public (register-new-ft-contract (ft-contract <ft-trait>) (deposit-fn-name (string-ascii 45)))
    (begin
        ;; Verify that tx-sender is an authorized miner
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        ;; Set up the assets that the contract is allowed to transfer
        (asserts! (map-insert allowed-contracts (contract-of ft-contract) deposit-fn-name) (err ERR_ASSET_ALREADY_ALLOWED))

        (ok true)
    )
)

(define-public (register-new-nft-contract (nft-contract <nft-trait>) (deposit-fn-name (string-ascii 45)))
    (begin
        ;; Verify that tx-sender is an authorized miner
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        ;; Set up the assets that the contract is allowed to transfer
        (asserts! (map-insert allowed-contracts (contract-of nft-contract) deposit-fn-name) (err ERR_ASSET_ALREADY_ALLOWED))

        (ok true)
    )
)

;; Helper function for fold: if a == b, return none; else return b
;; Returns (optional principal)
(define-private (is-principal-eq (miner-a principal) (search-for (optional principal)))
    (if (is-eq (some miner-a) search-for)
        none
        search-for
    )
)
;; Helper function: returns a boolean indicating whether the given principal is a miner
;; Returns bool
(define-private (is-miner (miner-to-check principal))
    (is-eq (some miner-to-check) (var-get  miner)))


;; Helper function: determines whether the commit-block operation satisfies pre-conditions
;; listed in `commit-block`.
;; Returns response<bool, int>
(define-private (can-commit-block? (commit-block-height uint)  (target-chain-tip (buff 32)))
    (begin
        ;; check no block has been committed at this height
        (asserts! (is-none (map-get? block-commits commit-block-height)) (err ERR_BLOCK_ALREADY_COMMITTED))

        ;; check that `target-chain-tip` matches the burn chain tip
        (asserts! (is-eq 
            target-chain-tip 
            (unwrap! (get-block-info? id-header-hash (- block-height u1)) (err ERR_CALLED_TOO_EARLY)) )
            (err ERR_INVALID_CHAIN_TIP)) 

        ;; check that the tx sender is one of the miners
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))

        ;; check that the miner called this contract directly
        (asserts! (is-miner contract-caller) (err ERR_INVALID_MINER))

        (ok true)
    )
)

;; Helper function: modifies the block-commits map with a new commit and prints related info
;; Returns response<(buff 32), ?>
(define-private (inner-commit-block (block (buff 32)) (commit-block-height uint) (withdrawal-root (buff 32)))
    (begin
        (map-set block-commits commit-block-height block)
        (map-set withdrawal-roots-map withdrawal-root true)
        (print { event: "block-commit", block-commit: block, withdrawal-root: withdrawal-root, block-height: commit-block-height })
        (ok block)
    )
)

;; Subnets miners call this to commit a block at a particular height.
;; `block` is the hash of the block being submitted.
;; `target-chain-tip` is the `id-header-hash` of the burn block (i.e., block on this chain) that
;;   the miner intends to build off.
;;
;; Fails if:
;;  1) we have already committed at this block height
;;  2) `target-chain-tip` is not the burn chain tip (i.e., on this chain)
;;  3) the sender is not a miner
(define-public (commit-block (block (buff 32)) (target-chain-tip (buff 32)) (withdrawal-root (buff 32)))
    (let ((commit-block-height block-height))
        (try! (can-commit-block? commit-block-height target-chain-tip))
        (inner-commit-block block commit-block-height withdrawal-root)
    )
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR NFT ASSET TRANSFERS

;; Helper function that transfers the specified NFT from the given sender to the given recipient. 
;; Returns response<bool, int>
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

(define-private (inner-mint-nft-asset (id uint) (sender principal) (recipient principal) (nft-mint-contract <mint-from-hyperchain-trait>))
    (let (
            (call-result (as-contract (contract-call? nft-mint-contract mint-from-hyperchain id sender recipient)))
            (mint-result (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
        )
        ;; Check that the transfer succeeded
        (asserts! mint-result (err ERR_MINT_FAILED))

        (ok true)
    )
)

(define-private (inner-transfer-or-mint-nft-asset (id uint) (recipient principal) (nft-contract <nft-trait>) (nft-mint-contract <mint-from-hyperchain-trait>))
    (let (
            (call-result (contract-call? nft-contract get-owner id))
            (nft-owner (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
            (contract-owns-nft (is-eq nft-owner (some CONTRACT_ADDRESS)))
            (no-owner (is-eq nft-owner none))
        )

        (if contract-owns-nft
            (inner-transfer-nft-asset id CONTRACT_ADDRESS recipient nft-contract)
            (if no-owner
                ;; Try minting the asset if there is no existing owner of this NFT
                (inner-mint-nft-asset id CONTRACT_ADDRESS recipient nft-mint-contract)
                ;; In this case, a principal other than this contract owns this NFT, so minting is not possible
                (err ERR_MINT_FAILED)
            )
        )
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
;; Returns response<bool, int>
(define-public (inner-withdraw-nft-asset (id uint) (recipient principal) (nft-contract <nft-trait>) (nft-mint-contract <mint-from-hyperchain-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (let (
            (hashes-are-valid (check-withdrawal-hashes withdrawal-root withdrawal-leaf-hash sibling-hashes))
         )

        (asserts! (try! hashes-are-valid) (err ERR_VALIDATION_FAILED))

        ;; TODO: should check leaf validity

        (asserts! (try! (as-contract (inner-transfer-or-mint-nft-asset id recipient nft-contract nft-mint-contract))) (err ERR_TRANSFER_FAILED))

        (asserts! 
          (finish-withdraw { withdrawal-leaf-hash: withdrawal-leaf-hash, withdrawal-root-hash: withdrawal-root })
          (err ERR_WITHDRAWAL_ALREADY_PROCESSED))
        
        (ok true)))

;; A user calls this function to withdraw the specified NFT from this contract. 
;; In order for this withdrawal to go through, the given withdrawal must have been included 
;; in a withdrawal Merkle tree a hyperchain miner submitted. The user must provide the leaf 
;; hash of their withdrawal and the root hash of the specific Merkle tree their withdrawal 
;; is included in. They must also provide a list of sibling hashes. The withdraw function 
;; uses the provided hashes to ensure the requested withdrawal is valid. 
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (withdraw-nft-asset (id uint) (recipient principal) (nft-contract <nft-trait>) (nft-mint-contract <mint-from-hyperchain-trait>)  (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (begin
        ;; Check that the asset belongs to the allowed-contracts map
        (unwrap! (map-get? allowed-contracts (contract-of nft-contract)) (err ERR_DISALLOWED_ASSET))

        (asserts! (try! (inner-withdraw-nft-asset id recipient nft-contract nft-mint-contract withdrawal-root withdrawal-leaf-hash sibling-hashes)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event
        (print { event: "withdraw-nft", nft-id: id, l1-contract-id: nft-contract, recipient: recipient })

        (ok true)
    )
)


;; Like `inner-transfer-or-mint-nft-asset but without allowing or requiring a mint function. In order to withdraw, the user must
;; have the appropriate balance.
(define-private (inner-transfer-without-mint-nft-asset (id uint) (recipient principal) (nft-contract <nft-trait>))
    (let (
            (call-result (contract-call? nft-contract get-owner id))
            (nft-owner (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
            (contract-owns-nft (is-eq nft-owner (some CONTRACT_ADDRESS)))
        )

        (asserts! contract-owns-nft (err ERR_NFT_NOT_OWNED_BY_CONTRACT))
        (inner-transfer-nft-asset id CONTRACT_ADDRESS recipient nft-contract)
    )
)

;; Like `inner-withdraw-nft-asset` but without allowing or requiring a mint function. In order to withdraw, the user must
;; have the appropriate balance.
(define-public (inner-withdraw-nft-asset-no-mint (id uint) (recipient principal) (nft-contract <nft-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (let (
            (hashes-are-valid (check-withdrawal-hashes withdrawal-root withdrawal-leaf-hash sibling-hashes))
         )

        (asserts! (try! hashes-are-valid) (err ERR_VALIDATION_FAILED))
        ;; TODO: should check leaf validity

        (asserts! (try! (as-contract (inner-transfer-without-mint-nft-asset id recipient nft-contract))) (err ERR_TRANSFER_FAILED))

        (ok           (finish-withdraw { withdrawal-leaf-hash: withdrawal-leaf-hash, withdrawal-root-hash: withdrawal-root })
)
    )
)

;; Like `withdraw-nft-asset` but without allowing or requiring a mint function. In order to withdraw, the user must
;; have the appropriate balance.
(define-public (withdraw-nft-asset-no-mint (id uint) (recipient principal) (nft-contract <nft-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (begin
        ;; Check that the asset belongs to the allowed-contracts map
        (unwrap! (map-get? allowed-contracts (contract-of nft-contract)) (err ERR_DISALLOWED_ASSET))

        ;; check that the tx sender is one of the miners
        ;; TODO: can remove this check once leaf validity is checked
        (asserts! (is-miner tx-sender) (err ERR_INVALID_MINER))
        
        (asserts! (try! (inner-withdraw-nft-asset-no-mint id recipient nft-contract withdrawal-root withdrawal-leaf-hash sibling-hashes)) (err ERR_TRANSFER_FAILED))

        ;; Emit a print event
        (print { event: "withdraw-nft", nft-id: id, l1-contract-id: nft-contract, recipient: recipient })

        (ok true)
    )
)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR FUNGIBLE TOKEN ASSET TRANSFERS

;; Helper function that transfers a specified amount of the fungible token from the given sender to the given recipient. 
;; Returns response<bool, int>
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

(define-private (inner-mint-ft-asset (amount uint) (sender principal) (recipient principal) (ft-mint-contract <mint-from-hyperchain-trait>))
    (let (
            (call-result (as-contract (contract-call? ft-mint-contract mint-from-hyperchain amount sender recipient)))
            (mint-result (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
        )
        ;; Check that the transfer succeeded
        (asserts! mint-result (err ERR_MINT_FAILED))

        (ok true)
    )
)

(define-private (inner-transfer-or-mint-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (ft-mint-contract <mint-from-hyperchain-trait>))
    (let (
            (call-result (contract-call? ft-contract get-balance CONTRACT_ADDRESS))
            (contract-ft-balance (unwrap! call-result (err ERR_CONTRACT_CALL_FAILED)))
            (contract-owns-enough (>= contract-ft-balance amount))
            (amount-to-transfer (if contract-owns-enough amount contract-ft-balance))
            (amount-to-mint (- amount amount-to-transfer))
        )

        ;; Check that the total balance between the transfer and mint is equal to the original balance
        (asserts! (is-eq amount (+ amount-to-transfer amount-to-mint)) (err ERR_IN_COMPUTATION))

        (if (> amount-to-transfer u0)
            (begin
                (try! (inner-transfer-ft-asset amount-to-transfer CONTRACT_ADDRESS recipient memo ft-contract))
                (if (> amount-to-mint u0)
                    (inner-mint-ft-asset amount-to-mint CONTRACT_ADDRESS recipient ft-mint-contract)
                    (ok true)
                )
            )
            (if (> amount-to-mint u0)
                (inner-mint-ft-asset amount-to-mint CONTRACT_ADDRESS recipient ft-mint-contract)
                (err ERR_ATTEMPT_TO_TRANSFER_ZERO_AMOUNT)
            )
        )
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
;; Returns response<bool, int>
(define-private (inner-withdraw-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (ft-mint-contract <mint-from-hyperchain-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (let (
            (hashes-are-valid (check-withdrawal-hashes withdrawal-root withdrawal-leaf-hash sibling-hashes))
         )

        (asserts! (try! hashes-are-valid) (err ERR_VALIDATION_FAILED))

        ;; TODO: should check leaf validity

        (asserts! (try! (as-contract (inner-transfer-or-mint-ft-asset amount recipient memo ft-contract ft-mint-contract))) (err ERR_TRANSFER_FAILED))

        (asserts! 
          (finish-withdraw { withdrawal-leaf-hash: withdrawal-leaf-hash, withdrawal-root-hash: withdrawal-root })
          (err ERR_WITHDRAWAL_ALREADY_PROCESSED))
        
        (ok true)))

;; A user can call this function to withdraw some amount of a fungible token asset from the 
;; contract and send it to a recipient. 
;; In order for this withdrawal to go through, the given withdrawal must have been included 
;; in a withdrawal Merkle tree a hyperchain miner submitted. The user must provide the leaf 
;; hash of their withdrawal and the root hash of the specific Merkle tree their withdrawal 
;; is included in. They must also provide a list of sibling hashes. The withdraw function 
;; uses the provided hashes to ensure the requested withdrawal is valid. 
;; The function emits a print with details of this event.
;; Returns response<bool, int>
(define-public (withdraw-ft-asset (amount uint) (recipient principal) (memo (optional (buff 34))) (ft-contract <ft-trait>) (ft-mint-contract <mint-from-hyperchain-trait>) (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool) ) )))
    (begin
        ;; Check that the withdraw amount is positive
        (asserts! (> amount u0) (err ERR_ATTEMPT_TO_TRANSFER_ZERO_AMOUNT))

        ;; Check that the asset belongs to the allowed-contracts map
        (unwrap! (map-get? allowed-contracts (contract-of ft-contract)) (err ERR_DISALLOWED_ASSET))

        (asserts! (try! (inner-withdraw-ft-asset amount recipient memo ft-contract ft-mint-contract withdrawal-root withdrawal-leaf-hash sibling-hashes)) (err ERR_TRANSFER_FAILED))

        (let (
                (ft-name (unwrap! (contract-call? ft-contract get-name) (err ERR_CONTRACT_CALL_FAILED)))
            )
            ;; Emit a print event 
            (print { event: "withdraw-ft", ft-amount: amount, l1-contract-id: ft-contract, recipient: recipient, ft-name: ft-name })
        )

        (ok true)
    )
)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; FOR STX TRANSFERS


;; Helper function that transfers the given amount from the specified fungible token from the given sender to the given recipient. 
;; Returns response<bool, int>
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
;; In order for this withdrawal to go through, the given withdrawal must have been included 
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

        (asserts! (try! hashes-are-valid) (err ERR_VALIDATION_FAILED))

        ;; TODO: should check leaf validity

        (asserts! (try! (as-contract (inner-transfer-stx amount tx-sender recipient))) (err ERR_TRANSFER_FAILED))

        (asserts! 
          (finish-withdraw { withdrawal-leaf-hash: withdrawal-leaf-hash, withdrawal-root-hash: withdrawal-root })
          (err ERR_WITHDRAWAL_ALREADY_PROCESSED))

        ;; Emit a print event 
        (print { event: "withdraw-stx", recipient: recipient, amount: amount })

        (ok true)
    )
)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; GENERAL WITHDRAWAL FUNCTIONS

;; This function concats the two given hashes in the correct order. It also prepends the buff `0x01`, which is 
;; a tag denoting a node (versus a leaf). 
;; Returns a buff
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
;; Returns (buff 32)
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
;; Returns response<bool, int>
(define-private (check-withdrawal-hashes (withdrawal-root (buff 32)) (withdrawal-leaf-hash (buff 32)) (sibling-hashes (list 50 (tuple (hash (buff 32)) (is-left-side bool)) )))
    (begin
        ;; Check that the user submitted a valid withdrawal root
        (asserts! (is-some (map-get? withdrawal-roots-map withdrawal-root)) (err ERR_INVALID_MERKLE_ROOT))

        ;; Check that this withdrawal leaf has not been processed before
        (asserts!
            (is-none 
             (map-get? processed-withdrawal-leaves-map
                       { withdrawal-leaf-hash: withdrawal-leaf-hash, withdrawal-root-hash: withdrawal-root }))
            (err ERR_WITHDRAWAL_ALREADY_PROCESSED))

        (let (
                (calculated-withdrawal-root (fold hash-help sibling-hashes withdrawal-leaf-hash))
                (roots-match (is-eq calculated-withdrawal-root withdrawal-root))
            )
            (if roots-match
                (ok true)
                (err ERR_MERKLE_ROOT_DOES_NOT_MATCH)
            )
        )
    )
)

;; This function should be called after the asset in question has been transferred. 
;; It adds the withdrawal leaf hash to a map of processed leaves. This ensures that 
;; this withdrawal leaf can't be used again to withdraw additional funds. 
;; Returns bool
(define-private (finish-withdraw (withdraw-info { withdrawal-leaf-hash: (buff 32), withdrawal-root-hash: (buff 32) }))
    (map-insert processed-withdrawal-leaves-map withdraw-info true))
