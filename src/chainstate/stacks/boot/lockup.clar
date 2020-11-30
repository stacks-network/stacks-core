(define-constant ERR_UNLOCK_UNREACHABLE 255)

(define-map vesting-schedules
    ((stx-block-height uint))
    ((entries 
        (list 4426 (tuple
            (beneficiary principal)
            (ustx-amount uint))))))

(define-private (grant-vesting (entry (tuple (beneficiary principal) (ustx-amount uint))))
    (unwrap-panic 
        (stx-transfer? (get ustx-amount entry) (as-contract tx-sender) (get beneficiary entry))))

(define-public (unlock-vesting-schedules (stx-block-height-opt (optional uint)))
    (let ((stx-block-height (default-to block-height stx-block-height-opt)))
        (asserts! (>= stx-block-height block-height) (err ERR_UNLOCK_UNREACHABLE))
        (let ((due-schedules (default-to (list) (get entries (map-get? vesting-schedules { stx-block-height: stx-block-height })))))
            (map grant-vesting due-schedules)
            (map-delete vesting-schedules { stx-block-height: stx-block-height })
            (ok (len due-schedules)))))

(define-public (register-vesting-schedules (stx-block-height uint) (entries (list 4426 (tuple (beneficiary principal) (ustx-amount uint)))))
    (begin
        (asserts! (is-eq block-height u0) (err ERR_UNLOCK_UNREACHABLE))
        (map-insert vesting-schedules { stx-block-height: stx-block-height } { entries: entries })
        (ok (len entries))))
