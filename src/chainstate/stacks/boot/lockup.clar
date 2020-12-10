(define-map vesting-schedules uint (list 4426 { recipient: principal, amount: uint }))

(define-read-only (get-vesting-schedules (stx-block-height-opt (optional uint)))
    (let ((stx-block-height (default-to block-height stx-block-height-opt)))
        (let ((due-schedules (default-to (list) (map-get? vesting-schedules stx-block-height))))
            (ok due-schedules))))
