        ;; stacker DB
        (define-read-only (stackerdb-get-signer-slots)
            (ok (list
                {
                    signer: 'ST24GDPTR7D9G3GFRR233JMWSD9HA296EXXG5XVGA,
                    num-slots: u10
                }
                {
                    signer: 'ST1MR26HR7MMDE847BE2QC1CTNQY4WKN9XDKNPEP3,
                    num-slots: u10
                }
                {
                    signer: 'ST110M4DRDXX2RF3W8EY1HCRQ25CS24PGY22DZ004,
                    num-slots: u10
                }
                {
                    signer: 'ST69990VH3BVCV39QWT6CJAVVA9QPB1715HTSN75,
                    num-slots: u10
                }
                {
                    signer: 'STCZSBZJK6C3MMAAW9N9RHSDKRKB9AKGJ2JMVDKN,
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
    