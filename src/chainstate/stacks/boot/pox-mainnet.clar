;; PoX mainnet constants
;; Min/max number of reward cycles uSTX can be locked for
(define-constant MIN-POX-REWARD-CYCLES u1)
(define-constant MAX-POX-REWARD-CYCLES u12)

;; Default length of the PoX registration window, in burnchain blocks.
(define-constant REGISTRATION-WINDOW-LENGTH u250)

;; Default length of the PoX reward cycle, in burnchain blocks.
(define-constant REWARD-CYCLE-LENGTH u1000)

;; Valid values for burnchain address versions.
;; TODO: These correspond to address hash modes in Stacks 2.0,
;;    but they should just be Bitcoin version bytes: we don't
;;    need to constrain PoX recipient addresses the way that
;;    we constrain other kinds of Bitcoin addresses
(define-constant ADDRESS-VERSION-P2PKH 0x00)
(define-constant ADDRESS-VERSION-P2SH 0x01)
(define-constant ADDRESS-VERSION-P2WPKH 0x02)
(define-constant ADDRESS-VERSION-P2WSH 0x03)

;; Stacking thresholds
(define-constant STACKING-THRESHOLD-25 u20000)
(define-constant STACKING-THRESHOLD-100 u5000)
