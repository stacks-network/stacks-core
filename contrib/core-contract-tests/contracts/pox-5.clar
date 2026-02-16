;; The caller is already staked
(define-constant ERR_ALREADY_STAKED (err u1))
(define-constant ERR_NOT_STAKED (err u2))
(define-constant ERR_INVALID_UNLOCK_BYTES_LENGTH (err u3))
(define-constant ERR_INSUFFICIENT_FUNDS (err u4))
;; The unlock height bytes are invalid
(define-constant ERR_INVALID_UNLOCK_HEIGHT_BYTES_LENGTH (err u5))
;; The unlock height is too soon
(define-constant ERR_INVALID_UNLOCK_HEIGHT_TOO_SOON (err u6))

;; Valid values for burnchain address versions.
;; These first four correspond to address hash modes in Stacks 2.1,
;; and are defined in pox-mainnet.clar and pox-testnet.clar (so they
;; cannot be defined here again).
(define-constant ADDRESS_VERSION_P2PKH 0x00)
(define-constant ADDRESS_VERSION_P2SH 0x01)
(define-constant ADDRESS_VERSION_P2WPKH 0x02)
(define-constant ADDRESS_VERSION_P2WSH 0x03)
(define-constant ADDRESS_VERSION_NATIVE_P2WPKH 0x04)
(define-constant ADDRESS_VERSION_NATIVE_P2WSH 0x05)
(define-constant ADDRESS_VERSION_NATIVE_P2TR 0x06)

;; Values for stacks address versions
(define-constant STACKS_ADDR_VERSION_MAINNET 0x16)
(define-constant STACKS_ADDR_VERSION_TESTNET 0x1a)

;; Keep these constants in lock-step with the address version buffs above
;; Maximum value of an address version as a uint
(define-constant MAX_ADDRESS_VERSION u6)
;; Maximum value of an address version that has a 20-byte hashbytes
;; (0x00, 0x01, 0x02, 0x03, and 0x04 have 20-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_20 u4)
;; Maximum value of an address version that has a 32-byte hashbytes
;; (0x05 and 0x06 have 32-byte hashbytes)
(define-constant MAX_ADDRESS_VERSION_BUFF_32 u6)

;; Default length of the PoX registration window, in burnchain blocks.
(define-constant PREPARE_CYCLE_LENGTH (if is-in-mainnet
    u100
    u50
))

;; Default length of the PoX reward cycle, in burnchain blocks.
(define-constant REWARD_CYCLE_LENGTH (if is-in-mainnet
    u2100
    u1050
))

;; Data vars that store a copy of the burnchain configuration.
;; Implemented as data-vars, so that different configurations can be
;; used in e.g. test harnesses.
(define-data-var pox-prepare-cycle-length uint PREPARE_CYCLE_LENGTH)
(define-data-var pox-reward-cycle-length uint REWARD_CYCLE_LENGTH)
(define-data-var first-burnchain-block-height uint u0)
(define-data-var configured bool false)
(define-data-var first-pox-4-reward-cycle uint u0)

(define-map stacking-state
    principal
    {
        l1-script-hash: (buff 34),
        signer-key: (buff 33),
        amount-ustx: uint,
        pox-addr: {
            version: (buff 1),
            hashbytes: (buff 32),
        },
    }
)

;; First item in the linked list of stackers
(define-data-var stacker-set-ll-first (optional principal) none)
;; Last item in the linked list of stackers
(define-data-var stacker-set-ll-last (optional principal) none)

;; Linked list of all stackers.
(define-map stacker-set-ll
    principal
    {
        prev: (optional principal),
        next: (optional principal),
    }
)

;; What's the reward cycle number of the burnchain block height?
;; Will runtime-abort if height is less than the first burnchain block (this is intentional)
(define-read-only (burn-height-to-reward-cycle (height uint))
    (/ (- height (var-get first-burnchain-block-height))
        (var-get pox-reward-cycle-length)
    )
)

;; What's the block height at the start of a given reward cycle?
(define-read-only (reward-cycle-to-burn-height (cycle uint))
    (+ (var-get first-burnchain-block-height)
        (* cycle (var-get pox-reward-cycle-length))
    )
)

;; What's the current PoX reward cycle?
(define-read-only (current-pox-reward-cycle)
    (burn-height-to-reward-cycle burn-block-height)
)

(define-read-only (get-stacker-info (stacker principal))
    (map-get? stacking-state stacker)
)

;;; Lock script helpers

;; Contruct an L1 lockup script
(define-read-only (construct-unlock-script
        (stacker principal)
        (unlock-burn-height (buff 3)) ;; (unlock-bytes-len (buff 2))
        (unlock-bytes (buff 255))
    )
    (let (
            (stacker-parts (unwrap-panic (principal-destruct? stacker)))
            (stacker-bytes (concat (get version stacker-parts) (get hash-bytes stacker-parts)))
            (unlock-bytes-len (uint-to-buff-le (len unlock-bytes)))
        )
        (concat 0x1605
            (concat stacker-bytes
                (concat 0x7503
                    (concat unlock-burn-height
                        (concat 0xb175 (concat unlock-bytes-len unlock-bytes))
                    ))
            ))
    )
)

;; Construct the p2wsh output script for a L1 lockup address
(define-read-only (construct-output-script
        (stacker principal)
        (unlock-burn-height (buff 3))
        (unlock-bytes (buff 255))
    )
    (concat 0x0020
        (sha256 (construct-unlock-script stacker unlock-burn-height unlock-bytes))
    )
)

;; Convert a u8 to a little-endian byte buffer,
;; ONLY FOR n < 256
(define-read-only (uint-to-buff-le (n uint))
    (unwrap-panic (as-max-len?
        (unwrap-panic (slice? (unwrap-panic (to-consensus-buff? n)) u16 u17))
        u1
    ))
)

;;; Public functions

(define-public (stake-stx
        (amount-ustx uint)
        (pox-addr {
            version: (buff 1),
            hashbytes: (buff 32),
        })
        (start-burn-ht uint)
        (signer-sig (optional (buff 65)))
        (signer-key (buff 33))
        (max-amount uint)
        (auth-id uint)
        (unlock-height-bytes (buff 3))
        (unlock-bytes (buff 255))
    )
    ;; this stacker's first reward cycle is the _next_ reward cycle
    (let (
            (first-reward-cycle (+ u1 (current-pox-reward-cycle)))
            (specified-reward-cycle (+ u1 (burn-height-to-reward-cycle start-burn-ht)))
            (unlock-script-hash (construct-output-script tx-sender unlock-height-bytes unlock-bytes))
            (unlock-height (buff-to-uint-le unlock-height-bytes))
        )
        ;; the start-burn-ht must result in the next reward cycle, do not allow stackers
        ;;  to "post-date" their `stack-stx` transaction
        ;; (asserts! (is-eq first-reward-cycle specified-reward-cycle)
        ;;           (err ERR_INVALID_START_BURN_HEIGHT))

        ;;;;  must be called directly by the tx-sender or by an allowed contract-caller
        ;; (asserts! (check-caller-allowed) (err ERR_STACKING_PERMISSION_DENIED))

        ;;;;  tx-sender principal must not be stacking
        (asserts! (is-none (get-stacker-info tx-sender)) ERR_ALREADY_STAKED)

        ;;;;  the Stacker must have sufficient unlocked funds
        (asserts! (>= (stx-get-balance tx-sender) amount-ustx)
            ERR_INSUFFICIENT_FUNDS
        )

        ;;;;  Validate ownership of the given signer key
        ;; (try! (consume-signer-key-authorization pox-addr (- first-reward-cycle u1) "stack-stx" lock-period signer-sig signer-key amount-ustx max-amount auth-id))

        ;;;;  ensure that stacking can be performed
        ;; (try! (can-stack-stx pox-addr amount-ustx first-reward-cycle lock-period))

        (try! (add-stacker-to-set tx-sender))

        (map-set stacking-state tx-sender {
            signer-key: signer-key,
            amount-ustx: amount-ustx,
            pox-addr: pox-addr,
            l1-script-hash: unlock-script-hash,
        })

        (ok {
            stacker: tx-sender,
            pox-addr: pox-addr,
            l1-script-hash: unlock-script-hash,
            unlock-height: unlock-height,
            amount-ustx: amount-ustx,
        })
    )
)

;;; Linked List functions

(define-read-only (get-stacker-set-last-item)
    (var-get stacker-set-ll-last)
)

(define-read-only (get-stacker-set-first-item)
    (var-get stacker-set-ll-first)
)

(define-read-only (get-stacker-set-item (stacker principal))
    (map-get? stacker-set-ll stacker)
)

(define-read-only (get-stacker-set-next-item (stacker principal))
    (match (map-get? stacker-set-ll stacker)
        item (get next item)
        none
    )
)

(define-read-only (get-stacker-set-prev-item (stacker principal))
    (match (map-get? stacker-set-ll stacker)
        item (get prev item)
        none
    )
)

(define-read-only (stacker-set-contains (stacker principal))
    (is-some (map-get? stacker-set-ll stacker))
)

(define-public (add-stacker-to-set (stacker principal))
    (let (
            (first-item (var-get stacker-set-ll-first))
            (last-item (var-get stacker-set-ll-last))
        )
        ;; Todo: remove this and guard in a higher-level fn
        (asserts! (not (is-some (map-get? stacker-set-ll stacker)))
            ERR_ALREADY_STAKED
        )

        (match last-item
            last-stacker (let ((last-node (unwrap-panic (map-get? stacker-set-ll last-stacker))))
                (map-set stacker-set-ll last-stacker {
                    prev: (get prev last-node),
                    next: (some stacker),
                })
                (map-set stacker-set-ll stacker {
                    prev: (some last-stacker),
                    next: none,
                })
            )
            (begin
                ;; This is the first item
                (map-set stacker-set-ll stacker {
                    prev: none,
                    next: none,
                })
                (var-set stacker-set-ll-first (some stacker)) ;; Stacker is the first item
            )
        )

        (var-set stacker-set-ll-last (some stacker))
        (ok true)
    )
)

(define-public (remove-stacker-from-set (stacker principal))
    (let (
            (first-item (var-get stacker-set-ll-first))
            (last-item (var-get stacker-set-ll-last))
            (node (unwrap! (map-get? stacker-set-ll stacker) (err ERR_NOT_STAKED)))
            (prev-item (get prev node))
            (next-item (get next node))
        )
        (match prev-item
            prev-stacker
            (let ((prev-node (unwrap-panic (map-get? stacker-set-ll prev-stacker))))
                (map-set stacker-set-ll prev-stacker {
                    prev: (get prev prev-node),
                    next: next-item,
                })
            )
            (var-set stacker-set-ll-first next-item) ;; This is the first item
        )

        (match next-item
            next-stacker
            (let ((next-node (unwrap-panic (map-get? stacker-set-ll next-stacker))))
                (map-set stacker-set-ll next-stacker {
                    prev: prev-item,
                    next: (get next next-node),
                })
            )
            (var-set stacker-set-ll-last prev-item) ;; This is the last item
        )
        (map-delete stacker-set-ll stacker)
        (ok true)
    )
)
