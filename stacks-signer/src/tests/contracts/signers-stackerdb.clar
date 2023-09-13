        ;; stacker DB
        (define-read-only (stackerdb-get-signer-slots)
            (ok (list
                {
                    signer: 'ST1RER7KAS4Q81ZTCA025SVSNZ73444NHG4D7BKWC,
                    num-slots: u10
                }
                {
                    signer: 'ST3WM0P0EWTVRA1EDWS9YFGDKV2A6A8N9TFANTSV9,
                    num-slots: u10
                }
                {
                    signer: 'ST2411R5HEBCKFQ8YKRANVFAJ8B6QNPEG9WHHP5TX,
                    num-slots: u10
                }
                {
                    signer: 'ST3N2XTMKWPWCGE3MC8EMDEP0C9CRB728M4EDZDNZ,
                    num-slots: u10
                }
                {
                    signer: 'ST2NHTSBDFQRJSCBKHFRWG5C0DS22G357CNQE1ZQ,
                    num-slots: u10
                }
                )))

        (define-read-only (stackerdb-get-config)
            (ok {
                chunk-size: u4096,
                write-freq: u0,
                max-writes: u4096,
                max-neighbors: u32,
                hint-replicas: (list )
            }))
    