(define-map lockups uint (list 4430 { recipient: principal, amount: uint }))

(define-read-only (get-lockups (stx-block-height-opt (optional uint)))
    (let ((stx-block-height (default-to block-height stx-block-height-opt)))
        (let ((due-schedules (default-to (list) (map-get? lockups stx-block-height))))
            (ok due-schedules))))
