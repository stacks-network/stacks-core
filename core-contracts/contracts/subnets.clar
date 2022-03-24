;; The .subnets contract

(define-constant CONTRACT_ADDRESS (as-contract tx-sender))

;; Error codes
(define-constant ERR_BLOCK_ALREADY_COMMITTED 1)
(define-constant ERR_INVALID_MINER 2)
(define-constant ERR_VALIDATION_FAILED 3)
(define-constant ERR_CONRACT_CALL_FAILED 4)
(define-constant ERR_TRANSFER_FAILED 5)
(define-constant ERR_MAP_INSERT_FAILED 6)
(define-constant ERR_TRANSFER_DOES_NOT_EXIST 7)
(define-constant ERR_ALREADY_ACKED 8)

;; Define data vars
(define-data-var nft-transfer-id uint 0)

;; Map from Stacks block height to block commit
(define-map block-commits uint (buff 32))
(define-map nft-transfer-map uint {transfer_ack: bool, withdraw_req: bool, withdraw_ack: bool})

;; List of miners
(define-constant miners (list 'SPAXYA5XS51713FDTQ8H94EJ4V579CXMTRNBZKSF 'SP3X6QWWETNBZWGBK6DRGTR1KX50S74D3433WDGJY
    'ST1AW6EKPGT61SQ9FNVDS17RKNWT8ZP582VF9HSCP 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5))

;; Testing info for 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5:
;;      secret_key: 7287ba251d44a4d3fd9276c88ce34c5c52a038955511cccaf77e61068649c17801
;;      btc_address: mr1iPkD9N3RJZZxXRk7xF9d36gffa6exNC

;; Use nft-trait
(use-trait nft-trait 'SP2PABAF9FTAJYNFZH93XENAJ8FVY99RRM50D2JG9.nft-trait.nft-trait)


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
(define-private (inner-commit-block (block (buff 32)) (commit-block-height uint))
    (begin
        (map-set block-commits commit-block-height block)
        (print { event: "block-commit", block-commit: block})
        (ok block)
    )
)

;; Subnets miners call this to commit a block at a particular height
(define-public (commit-block (block (buff 32)) (commit-block-height uint))
    (begin
        (unwrap! (can-commit-block? commit-block-height) (err ERR_VALIDATION_FAILED))
        (inner-commit-block block commit-block-height)
    )
)


;; Implement functions below in M2

;; FOR NFTs

(define-private (get-next-nft-transfer-id)
    (let (
        (next-transfer-id (var-get nft-transfer-id))
    )

    ;; generate next id
    (var-set nft-transfer-id (+ next-transfer-id 1))

    ;; return the next id
    (next-transfer-id)
    )
)

(define-private (inner-deposit-nft-asset)
    (let (
        (next-transfer-id get-next-nft-transfer-id)
        (map-update-outcome (map-insert nft-transfer-map next-transfer-id {transfer_ack: false, withdraw_req: false, withdraw_ack: false}))
    )
    (asserts! map-update-outcome (err ERR_MAP_INSERT_FAILED))

    (ok next-transfer-id)
    )
)

;; user: deposit asset
(define-public (deposit-nft-asset (id uint) (sender principal) (nft-contract <nft-trait>))
    (let (
        (call-result (contract-call? nft-contract transfer id sender CONTRACT_ADDRESS))
        (transfer-result (unwrap! call-result (err ERR_CONRACT_CALL_FAILED)))
        (transfer-outcome (unwrap! transfer-result (err ERR_TRANSFER_FAILED)))
    )
        (asserts! transfer-outcome (err ERR_TRANSFER_FAILED))

        (inner-deposit-nft-asset)
    )
)

;; miner: acknowledge deposit
(define-public (acknowledge-deposit (nft-transfer-id uint))
    (let (
        (map-entry-opt (map-get? nft-transfer-map nft-transfer-id))
        (map-entry (unwrap! map-entry-opt (err ERR_TRANSFER_DOES_NOT_EXIST)))
    )
        (asserts! (get transfer-ack map-entry) (err ERR_ALREADY_ACKED))

        ;; ***** USE MERGE HERE INSTEAD
        (asserts! (map-set nft-transfer-map nft-transfer-id {transfer_ack: true, withdraw_req: false, withdraw_ack: false}) (err ERR_MAP_INSERT_FAILED))

        (ok nft-transfer-id)
    )
)

;; user: issue withdraw request

;; miner: approve withdraw