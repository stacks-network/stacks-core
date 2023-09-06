;; title: signers-dkg
;; version:
;; summary: Signer StackerDB test contract
;; description:

;; traits
;;
(impl-trait 'ST1NXBK3K5YYMD6FD41MVNP3JS1GABZ8TRVX023PT.sip-010-trait-ft-standard.sip-010-trait)

(define-read-only (stackerdb-get-signer-slots)
    (ok (list
        {
            signer: 'ST2S05M62W9J94F6Z2YEPKSMMHHFCSAEVVCF01WWE,
            num-slots: u16
        }
        {
            signer: 'STB1HK64HJKE3TKW4JJ9KV9FG78DDFNADQZVVNJT,
            num-slots: u16
        }
        {
            signer: 'ST3DHSJ3YRGRPRD5MA457YPD7N2Y2E7RQRH6T5E36,
            num-slots: u16
        }
        {
            signer: 'STWVA0RJYMNJW7RRXMGQ4TBNCFQYPGVK7Z7P5EVY,
            num-slots: u16
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