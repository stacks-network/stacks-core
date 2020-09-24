;; The .lockup boot contract
;; Error codes
(define-constant ERR_UNLOCK_UNREACHABLE 255)

;; Map for all locked STX that will later unlock.
;; Entries in this map exist from Stacks 1.0.  These are tokens that were purchased
;; in one or more of the token sales from Blockstack PBC and its subsidiaries.
;; Some of these tokens are illiquid until certain block heights are reached.
;; This map encodes these block heights, and binds them to their owner and unlock
;; amount.
;; 
;; This map is populated in the boot block from data pulled from the
;; Stacks 1.0 genesis block.  No smart contract can add to this map.
;; Rows are deleted from this map once they're processed.
;;
;; The map here is structured like an array.  Each block height is coupled with
;; an index ranging from 0 to the number of principals who unlock tokens in this
;; block height, and that number of principals is stored in the internal-locked-stx-len
;; The miner and block-processing code will use this map and the internal-locked-stx-len
;; map to iterate through each Stacks block's rows and process them via the
;; private (internal-unlock-stx) method.  The node's Clarity VM will take care of
;; calling the method; no smart contracts will ever interact with this state
;; directly.
(define-map internal-locked-stx
    ;; the `lock-send` value from the original DB, and an index
    ((stx-height uint) (index uint))
    (
        ;; who owns these tokens
        (owner principal)
        ;; digest of associated metadata with the purchase
        (metadata (buff 32))
        ;; amount to unlock, in uSTX
        (unlock-ustx uint)
    )
)

;; Number of entries for a particular Stacks block height in the internal-locked-stx map.
;; This information is derived from the Stacks 1.0 genesis block.
(define-map internal-locked-stx-len
    ((stx-height uint))
    ((len uint))
)

;; Map each owner-principal and index to its unlock height.
;; The maximum index value is stored for each principal in owner-unlocks-len
(define-map owner-unlock-heights
    ((owner principal) (index uint))
    ((stx-height uint))
)

;; Map each owner-principal to its number of unlock heights.
;; This is automatically populated when the Stacks 1.0 genesis block gets imported.
(define-map owner-unlock-heights-len
    ((owner principal))
    ((len uint))
)

;; Total number of additional tokens unlocked at a particular Stacks block height.
;; Used to calculate the number of liquid STX at each block, which is needed for
;; PoX.
(define-map unlocked-stx-per-block
    ((stx-height uint))
    ((total-unlocked uint))
)

;; Unlock someone's STX for this block.
;; This is a private method (not callable from smart contracts), but is called by the
;; miner and by the block-processing code in the Stacks node directly to ensure that purchased
;; tokens unlock at the right block heights.  The miner / block-processor uses the
;; locked-stx-len map to determine the possible values for index, and iterates over
;; the rows in locked-stx to process each token owner's token unlocks.
;; If this method fails -- i.e. returns (err ...), then the Stacks node aborts.
(define-private (internal-unlock-stx (index uint))
    (let (
        ;; If there's no unlock data, then it's a fatal node error.
        ;; No one's tokens should be unlocked twice, and the node shouldn't ever ask
        ;; to unlock tokens that don't exist.
        (unlock-data
            (unwrap!
                (map-get? internal-locked-stx { stx-height: block-height, index: index })
                (err ERR_UNLOCK_UNREACHABLE)))

        (this-contract (as-contract tx-sender))
    )
    (unwrap!
        (stx-transfer? (get unlock-ustx unlock-data) this-contract (get owner unlock-data))
        (err ERR_UNLOCK_UNREACHABLE))
    
    ;; never process this row again
    (map-delete internal-locked-stx { stx-height: block-height, index: index })
    (ok true))
)

;; Determine how many principals need to have their tokens unlocked at this block height.
;; This is only called by the miner / node internally, so it can call (internal-unlock-stx).
(define-private (internal-get-num-unlocks)
    (default-to
        u0
        (get len (map-get? internal-locked-stx-len { stx-height: block-height })))
)

;; Schedule a token unlock record at a particular Stacks block height, for a particular owner.
;; Used only during the Stacks 1.0 import to populate this contract's tables.
;; NOTE: should be called in ascending order in block height
(define-private (schedule-token-unlock (owner principal) (stx-height uint) (unlock-ustx uint) (metadata (buff 32)))
    (let (
        (cur-stx-unlock-len
            (default-to
                u0
                (get len (map-get? internal-locked-stx-len { stx-height: stx-height }))))

        (cur-owner-unlock-len
            (default-to
                u0
                (get len (map-get? owner-unlock-heights-len { owner: owner } ))))

        (cur-stx-unlocked
            (default-to
                u0
                (get total-unlocked (map-get? unlocked-stx-per-block { stx-height: stx-height }))))
    )
    ;; Add unlock record
    (map-set internal-locked-stx
        { stx-height: stx-height, index: cur-stx-unlock-len }
        {
            owner: owner,
            metadata: metadata,
            unlock-ustx: unlock-ustx
        }
    )

    (map-set internal-locked-stx-len { stx-height: stx-height } { len: (+ u1 cur-stx-unlock-len) })

    ;; Add owner unlock height
    (map-set owner-unlock-heights
        { owner: owner, index: cur-owner-unlock-len }
        { stx-height: stx-height }
    )

    (map-set owner-unlock-heights-len { owner: owner } { len: (+ u1 cur-owner-unlock-len) })

    ;; Update the total amount of uSTX to be unlocked at this height.
    (map-set unlocked-stx-per-block { stx-height: stx-height } { total-unlocked: (+ unlock-ustx cur-stx-unlocked) })
    )
)
