;;;; Errors
;; todo(ludo): should err be returning strings instead?
(define-constant err-panic 0)
(define-constant err-namespace-preorder-not-found 1001)
(define-constant err-namespace-preorder-expired 1002)
(define-constant err-namespace-preorder-already-exists 1003)
(define-constant err-namespace-unavailable 1004)
(define-constant err-namespace-not-found 1005)
(define-constant err-namespace-already-exists 1006)
(define-constant err-namespace-not-launched 1007)
(define-constant err-namespace-price-function-invalid 1008)
(define-constant err-namespace-preorder-claimability-expired 1009)
(define-constant err-namespace-launchability-expired 1010)
(define-constant err-namespace-operation-unauthorized 1011)
(define-constant err-namespace-stx-burnt-insufficient 1012)
(define-constant err-namespace-blank 1013)
(define-constant err-namespace-already-launched 1014)

(define-constant err-name-preorder-not-found 2001)
(define-constant err-name-preorder-expired 2002)
(define-constant err-name-preorder-funds-insufficient 2003)
(define-constant err-name-unavailable 2004)
(define-constant err-name-namespace-not-found 2005)
(define-constant err-name-operation-unauthorized 2006)
(define-constant err-name-stx-burnt-insufficient 2007)
(define-constant err-name-expired 2008)
(define-constant err-name-grace-period 2009)
(define-constant err-name-blank 2010)
(define-constant err-name-already-claimed 2011)
(define-constant err-name-claimability-expired 2012)
(define-constant err-name-not-found 2013)
(define-constant err-name-revoked 2014)
(define-constant err-name-transfer-failed 2015)

(define-constant err-principal-already-associated 3001)
(define-constant err-not-implemented 0)

;;;; Constants

;; TTL
;; todo(ludo): add real values
(define-constant namespace-preorder-claimability-ttl u10)
(define-constant namespace-launchability-ttl u10)
(define-constant name-preorder-claimability-ttl u10)

;; Price tables
;; todo(ludo): how do we adjust stx-price?
(define-constant stx-to-usd-cents 15)
(define-constant stx-to-micro-stx 1000000)
(define-constant namespace-1-char (/ (* 96000 stx-to-micro-stx) stx-to-usd-cents))
(define-constant namespace-2-to-3-char (/ (* 9600 stx-to-micro-stx) stx-to-usd-cents))
(define-constant namespace-4-to-7-char (/ (* 960 stx-to-micro-stx) stx-to-usd-cents))
(define-constant namespace-8-to-20-char (/ (* 96 stx-to-micro-stx) stx-to-usd-cents))
(define-constant namespace-price-table (list
  namespace-1-char
  namespace-2-to-3-char
  namespace-2-to-3-char
  namespace-4-to-7-char
  namespace-4-to-7-char
  namespace-4-to-7-char
  namespace-4-to-7-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char
  namespace-8-to-20-char))
;; todo(ludo): "a" vs "A"?
(define-constant discounted-vowels (list
  "a" "e" "i" "o" "u" "y"))
(define-constant discounted-non-alpha-chars (list
  "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "-" "_"))

;; todo(ludo): feature request?
;; (define-type price-function-type (tuple (buckets (list 16 uint))
;;                                         (base uint)
;;                                         (coeff uint)
;;                                         (nonalpha-discount uint)
;;                                         (no-voyel-discount uint)))

;;;; Data
(define-map namespaces
  ((namespace (buff 20)))
  ((name-importer principal)
   (revealed-at uint)
   (launched-at (optional uint))
   (namespace-version uint)
   (renewal-rule uint)
   (price-function (tuple (buckets (list 16 uint)) (base uint) (coeff uint) (nonalpha-discount uint) (no-voyel-discount uint)))))

(define-map namespace-preorders
  ((hashed-namespace (buff 20)) (buyer principal))
  ((created-at uint) (claimed bool) (stx-burned uint)))

;; todo(ludo): fix name and namespace sizes.
;; according https://docs.blockstack.org/core/wire-format.html
;; "namespace" = 20, "name" = 16? what about subdomains/sponsored names?
(define-non-fungible-token names (tuple (name (buff 16)) (namespace (buff 20))))

(define-map owner-name ((owner principal)) ((name (buff 16)) (namespace (buff 20))))

(define-map name-properties
  ((name (buff 16)) (namespace (buff 20)))
  ((registered-at (optional uint))
   (imported-at (optional uint))
   (revoked-at (optional uint))))
;; todo(ludo): bind a hash of the zonefile

(define-map name-preorders
  ((hashed-fqn (buff 20)) (buyer principal))
  ((created-at uint) (claimed bool) (stx-burned uint)))

(define-map zonefiles
  ((name (buff 16)) (namespace (buff 20)))
  ((content (buff 40960)) (updated-at uint)))

;; todo(ludo): implement sponsored names, but need a back and forth with the team on the strategy:
;; are we splitting FQNs on-chain, or keep passing components (namespace/name/sponsored_name).
(define-map sponsors
  ((name (buff 20)) (namespace (buff 20)))
  ((content (buff 40960))))

(define-private (compute-namespace-price (namespace (buff 20)))
  u0)
;;  (let ((namespace-len (fold increment-len namespace 0)))
;;    (asserts 
;;     (> namespace-len 0)
;;      (err err-namespace-blank))
    ;; todo(ludo): feature request?
;;    (get-i namespace-len namespace-price-table)))

(define-private (compute-name-price (name (buff 16))
                                    (price-function (tuple (buckets (list 16 uint)) (base uint) (coeff uint) (nonalpha-discount uint) (no-voyel-discount uint))))
  u0)
;;   (let ((name-len (fold increment-len name 0)))
;;    (asserts 
;;      (> name-len 0)
;;      (err err-name-blank))
    ;; todo(ludo): feature request?
    ;; Check for vowels discounts
    ;; Check for non-alpha-discounts
;;    (get-i name-len buckets)))

;; todo(ludo): to implement
(define-private (has-name-expired (namespace (buff 20)) (name (buff 16)))
  'true)

;; todo(ludo): to implement
(define-private (is-name-in-grace-period (namespace (buff 20)) (name (buff 16)))
  'false)

;; todo(ludo): to implement
(define-private (buff-lowercased (namespace (buff 20)))
  namespace)

(define-private (is-buyer-already-owning-name (owner principal))
  'true)

(define-private (can-user-own-name (owner principal))
  'true)

;;;; NAMESPACES

;; NAMESPACE_PREORDER
;; This step registers the salted hash of the namespace with BNS nodes, and burns the requisite amount of cryptocurrency.
;; Additionally, this step proves to the BNS nodes that user has honored the BNS consensus rules by including a recent
;; consensus hash in the transaction.
;; Returns pre-order's expiration date (in blocks).
(define-public (namespace-preorder (hashed-namespace (buff 20))
                                   (stx-to-burn uint))
  (begin
    (asserts!
      (is-none? (map-get namespace-preorders ((hashed-namespace hashed-namespace) (buyer contract-caller))))
      (err err-namespace-preorder-already-exists))
    ;; Burn the tokens
    ;; todo(ludo): we are missing stx-burn! native function
    (map-set! namespace-preorders
      ((hashed-namespace hashed-namespace) (buyer contract-caller))
      ((created-at block-height) (claimed 'false) (stx-burned stx-to-burn)))
    ;; todo(ludo): don't improvise, look at the returned values in the codebase
    (ok (+ block-height namespace-preorder-claimability-ttl))))

;; NAMESPACE_REVEAL
;; This second step reveals the salt and the namespace ID (pairing it with its NAMESPACE_PREORDER). It reveals how long
;; names last in this namespace before they expire or must be renewed, and it sets a price function for the namespace
;; that determines how cheap or expensive names its will be.
;; Note (1): in the original implementation, the hash of the namespace is being salted so that 2 users preordering the same
;; namespace wouldn't collide. In this implementation, the hashed-namespace is associated in a tuple, with the principal
;; of the user.
(define-public (namespace-reveal (namespace (buff 20))
                                 (namespace-version uint)
                                 (price-function (tuple (buckets (list 16 uint)) (base uint) (coeff uint) (nonalpha-discount uint) (no-voyel-discount uint)))
                                 (renewal-rule uint)
                                 (name-importer principal))
  ;; The salt and namespace must hash to a preorder entry in the `namespace_preorders` table.
  ;; The sender must match the principal in the preorder entry (implied)
  (let ((hashed-namespace (hash160 namespace))
        (preorder (expects!
          (map-get namespace-preorders ((hashed-namespace (hash160 namespace)) (buyer tx-sender))) ;; todo(ludo): tx-sender or contract-caller?
          (err err-namespace-preorder-not-found)))
        (lowercased-namespace (buff-lowercased namespace)))
    ;; The namespace must not exist yet in the `namespaces` table
    (asserts!
      (is-none? (map-get namespaces ((namespace lowercased-namespace))))
      (err err-namespace-already-exists))
    ;; The amount burnt must be equal to or greater than the cost of the namespace
    (asserts!
      (> (get stx-burned preorder) (compute-namespace-price lowercased-namespace))
      (err err-namespace-stx-burnt-insufficient))
    ;; todo(ludo): validate the price function inputs
    ;; This transaction must arrive within 24 hours of its `NAMESPACE_PREORDER`
    (asserts!
      (< block-height (+ (get created-at preorder) namespace-preorder-claimability-ttl))
      (err err-namespace-preorder-claimability-expired))
    ;; The preorder record for this namespace will be marked as "claimed"
    (map-set! namespace-preorders
      ((hashed-namespace hashed-namespace) (buyer tx-sender))
      ((created-at (get created-at preorder)) (claimed 'true) (stx-burned (get stx-burned preorder))))
    ;; The namespace will be set as "revealed" but not "launched", its price function, its renewal rules, its version,
    ;; and its import principal will be written to the  `namespaces` table.
    ;; Name should be lowercased.
    (ok (map-set! namespaces
      ((namespace lowercased-namespace))
      ((name-importer name-importer)
       (revealed-at block-height)
       (launched-at none)
       (namespace-version namespace-version)
       (renewal-rule renewal-rule)
       (price-function price-function))))))

;; NAME_IMPORT
;; Once a namespace is revealed, the user has the option to populate it with a set of names. Each imported name is given
;; both an owner and some off-chain state. This step is optional; Namespace creators are not required to import names.
(define-public (name-import (namespace (buff 20))
                            (name (buff 16))
                            (zonefile-content (buff 40960)))
  (let ((namespace-props
        (expects!
          (map-get namespaces ((namespace namespace)))
          (err err-namespace-not-found))))
    ;; The name's namespace must not be launched
    (asserts!
      (is-none? (get launched-at namespace-props))
      (err err-namespace-already-launched))
    ;; Less than 1 year must have passed since the namespace was "revealed"
    (asserts!
      (< block-height (+ (get revealed-at namespace-props) namespace-launchability-ttl))
      (err err-namespace-launchability-expired))
    ;; The sender principal must match the namespace's import principal
    (asserts!
      (eq? (get name-importer namespace-props) tx-sender) ;; todo(ludo): tx-sender or contract-caller?
      (err err-namespace-operation-unauthorized))
    ;; Mint the new name
    (nft-mint! names (tuple (namespace namespace) (name name)) tx-sender) ;; todo(ludo): tx-sender or contract-caller? nft-mint! or nft-mint? ?
    ;; The namespace will be set as "revealed" but not "launched", its price function, its renewal rules, its version, and its import principal will be written to the  `namespaces` table
    (map-set! name-properties
      ((namespace namespace) (name name))
      ((registered-at none)
       (imported-at (some block-height))
       (revoked-at none)))
    ;; Import the zonefile
    (map-set! zonefiles
      ((namespace namespace) (name name))
      ((updated-at block-height)
       (content zonefile-content)))
    (ok 1)))

;; NAMESPACE_READY
;; The final step of the process launches the namespace and makes the namespace available to the public. Once a namespace
;; is launched, anyone can register a name in it if they pay the appropriate amount of cryptocurrency.
(define-public (namespace-ready (namespace (buff 20)))
  (let ((namespace-props
        (expects!
          (map-get namespaces ((namespace namespace)))
          (err err-namespace-not-found))))
    ;; The name's namespace must not be launched
    (asserts!
      (is-none? (get launched-at namespace-props))
      (err err-namespace-already-launched))
    ;; Less than 1 year must have passed since the namespace was "revealed"
    (asserts!
      (< block-height (+ (get revealed-at namespace-props) namespace-launchability-ttl))
      (err err-namespace-launchability-expired))
    ;; todo(ludo): Check owner-name
    ;; The sender principal must match the namespace's import principal
    (asserts!
      (eq? (get name-importer namespace-props) tx-sender) ;; todo(ludo): tx-sender or contract-caller?
      (err err-namespace-operation-unauthorized))
    ;; The namespace will be set as "revealed" but not "launched", its price function, its renewal rules, its version, and its import principal will be written to the  `namespaces` table
    (ok (map-set! namespaces
      ((namespace namespace))
      ((launched-at (some block-height))
       (name-importer (get name-importer namespace-props))
       (revealed-at (get revealed-at namespace-props))
       (namespace-version (get namespace-version namespace-props))
       (renewal-rule (get renewal-rule namespace-props))
       (price-function (get price-function namespace-props)))))))

;;;; NAMES

;; NAME_PREORDER
;; This is the first transaction to be sent. It tells all BNS nodes the salted hash of the BNS name,
;; and it pays the registration fee to the namespace owner's designated address
(define-public (name-preorder (hashed-fqn (buff 20))
                              (stx-to-burn uint))
  (begin
    (asserts!
      (is-none? (map-get name-preorders ((hashed-fqn hashed-fqn) (buyer tx-sender)))) ;; todo(ludo): tx-sender or contract-caller?
      (err err-namespace-preorder-already-exists))
    ;; Burn the tokens
    ;; todo(ludo): we are missing stx-burn! native function
    (map-set! name-preorders
      ((hashed-fqn hashed-fqn) (buyer tx-sender))
      ((created-at block-height) (stx-burned stx-to-burn) (claimed 'false)))
    (ok (+ block-height name-preorder-claimability-ttl))))

;; NAME_REGISTRATION
;; This is the second transaction to be sent. It reveals the salt and the name to all BNS nodes,
;; and assigns the name an initial public key hash and zone file hash
(define-public (name-register (namespace (buff 20))
                              (name (buff 16))
                              (zonefile-content (buff 40960)))
  (let (
    (hashed-fqn (hash160 (concat (concat name ".") namespace)))
    (current-owned-name (map-get owner-name ((owner tx-sender)))))
    (let ( 
        (preorder (expects!
          (map-get name-preorders ((hashed-fqn hashed-fqn) (buyer tx-sender))) ;; todo(ludo): tx-sender or contract-caller?
          (err err-name-preorder-not-found)))
        (namespace-props (expects!
          (map-get namespaces ((namespace namespace)))
          (err err-namespace-not-found)))
        (can-sender-buy-name (if (is-none? current-owned-name)
                                 'true
                                 (has-name-expired 
                                   (expects! (get namespace current-owned-name) (err err-panic))
                                   (expects! (get name current-owned-name) (err err-panic))))))
      ;; The name must not exist yet, or be expired
      (if (is-none? (nft-get-owner names (tuple (name name) (namespace namespace)))) ;; todo(ludo): implicit tuple syntax not available here.
        'true
        (asserts!
          (has-name-expired namespace name)
          (err err-name-unavailable)))
      ;; The name's namespace must be launched
      (asserts!
        (eq? (is-none? (get launched-at namespace-props)) 'false) ;; todo(ludo): is-some? would be more readable.
        (err err-namespace-not-launched))
      ;; The preorder entry must be unclaimed
      (asserts!
        (eq? (get claimed preorder) 'false)
        (err err-name-already-claimed))
      ;; Less than 24 hours must have passed since the name was preordered
      (asserts!
        (< block-height (+ (get created-at preorder) name-preorder-claimability-ttl))
        (err err-name-claimability-expired))
      ;; The amount burnt must be equal to or greater than the cost of the namespace
      (asserts!
        (> (get stx-burned preorder) (compute-name-price name (get price-function namespace-props)))
        (err err-name-stx-burnt-insufficient))
      ;; The principal can buy a name
      (asserts!
        can-sender-buy-name
        (err err-principal-already-associated))
      ;; Mint the new name
      (nft-mint! names (tuple (namespace namespace) (name name)) tx-sender) ;; todo(ludo): tx-sender or contract-caller?
      ;; The namespace will be set as "revealed" but not "launched", its price function, its renewal rules, its version, and its import principal will be written to the  `namespaces` table
      (map-set! name-properties
        ((namespace namespace) (name name))
        ((registered-at (some block-height))
        (imported-at none)
        (revoked-at none)))
      (map-set! owner-name
        ((owner tx-sender))
        ((namespace namespace) (name name)))
      ;; Import the zonefile
      (map-set! zonefiles
        ((namespace namespace) (name name))
        ((updated-at block-height)
        (content zonefile-content)))
      (ok 1))))

;; NAME_UPDATE
(define-public (name-update (namespace (buff 20))
                            (name (buff 16))
                            (zonefile-content (buff 40960)))
  (let (
    (owner (expects!
      (nft-get-owner names (tuple (name name) (namespace namespace)))
      (err err-name-not-found))) ;; The name must exist
    (name-props (expects!
      (map-get name-properties ((name name) (namespace namespace)))
      (err err-name-not-found)))) ;; The name must exist
    ;; The sender must match the name's current owner
    (asserts!
      (eq? owner tx-sender) ;; todo(ludo): tx-sender or contract-caller?
      (err err-name-operation-unauthorized))
    ;; The name must not be expired
    (asserts!
      (eq? (has-name-expired namespace name) 'false) ;; todo(ludo): refactor has-name-expired signature?
      (err err-name-expired))
    ;; The name must not be in the renewal grace period
    (asserts!
      (eq? (is-name-in-grace-period namespace name) 'false) ;; todo(ludo): refactor is-name-in-grace-period signature?
      (err err-name-grace-period))
    ;; The name must not be revoked
    (asserts!
      (is-none? (get revoked-at name-props))
      (err err-name-revoked))
    ;; Update the zonefile
    (map-set! zonefiles
      ((namespace namespace) (name name))
      ((updated-at block-height)
       (content zonefile-content)))
    (ok 1)))

;; NAME_TRANSFER
(define-public (name-transfer (namespace (buff 20))
                              (name (buff 16))
                              (new-owner principal)
                              (zonefile-content (optional (buff 40960))))
  (let ((current-owned-name (map-get owner-name ((owner new-owner)))))
    (let (
      (owner (expects!
        (nft-get-owner names (tuple (name name) (namespace namespace)))
        (err err-name-not-found))) ;; The name must exist
      (name-props (expects!
        (map-get name-properties ((name name) (namespace namespace)))
        (err err-name-not-found))) ;; The name must exist
      (can-new-owner-get-name (if (is-none? current-owned-name)
                                  'true
                                  (has-name-expired 
                                    (expects! (get namespace current-owned-name) (err err-panic))
                                    (expects! (get name current-owned-name) (err err-panic))))))
      ;; The sender must match the name's current owner
      (asserts!
        (eq? owner tx-sender) ;; todo(ludo): tx-sender or contract-caller?
        (err err-name-operation-unauthorized))
      ;; The name must not be expired
      (asserts!
        (eq? (has-name-expired namespace name) 'false) ;; todo(ludo): refactor has-name-expired signature?
        (err err-name-expired))
      ;; The name must not be in the renewal grace period
      (asserts!
        (eq? (is-name-in-grace-period namespace name) 'false) ;; todo(ludo): refactor is-name-in-grace-period signature?
        (err err-name-grace-period))
      ;; The name must not be revoked
      (asserts!
        (is-none? (get revoked-at name-props))
        (err err-name-revoked))
      ;; The new owner does not own a name
      (asserts!
        can-new-owner-get-name
        (err err-principal-already-associated))
      ;; Burn the tokens
      ;; todo(ludo): missing stx-to-burn
      ;; Transfer the name
      (expects!
        (nft-transfer! names
                      (tuple (name name) (namespace namespace))
                      tx-sender
                      new-owner) ;; tx-sender or contract-caller?
        (err err-name-transfer-failed))
      (map-set! owner-name
        ((owner new-owner))
        ((namespace namespace) (name name)))
      ;; Update the zonefile, if any.
      (if (is-none? zonefile-content)
        'true
        (map-set! zonefiles
          ((namespace namespace) (name name))
          ((updated-at block-height)
          (content (expects! zonefile-content (err err-panic))))))
      (ok 1))))

;; NAME_REVOKE
(define-public (name-revoke (namespace (buff 20))
                            (name (buff 16)))
  (let (
    (owner (expects!
      (nft-get-owner names (tuple (name name) (namespace namespace)))
      (err err-name-not-found))) ;; The name must exist
    (name-props (expects!
      (map-get name-properties ((name name) (namespace namespace)))
      (err err-name-not-found)))) ;; The name must exist
    ;; The sender must match the name's current owner
    (asserts!
      (eq? owner tx-sender) ;; todo(ludo): tx-sender or contract-caller?
      (err err-name-operation-unauthorized))
    ;; The name must not be expired
    (asserts!
      (eq? (has-name-expired namespace name) 'false) ;; todo(ludo): refactor has-name-expired signature?
      (err err-name-expired))
    ;; The name must not be in the renewal grace period
    (asserts!
      (eq? (is-name-in-grace-period namespace name) 'false) ;; todo(ludo): refactor is-name-in-grace-period signature?
      (err err-name-grace-period))
    ;; The name must not be revoked
    (asserts!
      (is-none? (get revoked-at name-props))
      (err err-name-revoked))
    ;; Update the zonefile
    (map-set! name-properties
      ((namespace namespace) (name name))
      ((registered-at (get registered-at name-props))
       (imported-at (get imported-at name-props))
       (revoked-at (some block-height))))
    (ok 1)))

;; NAME_RENEWAL
(define-public (name-renewal (namespace (buff 20))
                             (name (buff 16))
                             (stx-to-burn uint)
                             (new-owner (optional principal))
                             (zonefile-content (optional (buff 40960))))
  (let (
    (namespace-props (expects!
      (map-get namespaces ((namespace namespace)))
      (err err-namespace-not-found)))
    (owner (expects!
      (nft-get-owner names (tuple (name name) (namespace namespace)))
      (err err-name-not-found))) ;; The name must exist
    (name-props (expects!
      (map-get name-properties ((name name) (namespace namespace)))
      (err err-name-not-found)))) ;; The name must exist
    ;; The sender must match the name's current owner
    (asserts!
      (eq? owner tx-sender) ;; todo(ludo): tx-sender or contract-caller?
      (err err-name-operation-unauthorized))
    ;; The name must not be expired
    (asserts!
      (eq? (has-name-expired namespace name) 'false) ;; todo(ludo): refactor has-name-expired signature?
      (err err-name-expired))
    ;; The name must not be in the renewal grace period
    (asserts!
      (eq? (is-name-in-grace-period namespace name) 'false) ;; todo(ludo): refactor is-name-in-grace-period signature?
      (err err-name-grace-period))
    ;; The amount burnt must be equal to or greater than the cost of the namespace
    (asserts!
      (> stx-to-burn (compute-name-price name (get price-function namespace-props)))
      (err err-name-stx-burnt-insufficient))
    ;; The name must not be revoked
    (asserts!
      (is-none? (get revoked-at name-props))
      (err err-name-revoked))
    ;; Transfer the name, if any new-owner
    (if (is-none? new-owner)
      (ok 'false) 
      (let ((owner-unwrapped (expects! new-owner (err err-panic))))
        (let ((current-owned-name (map-get owner-name ((owner owner-unwrapped)))))
          (let ((can-new-owner-get-name (if (is-none? current-owned-name)
                                  'true
                                  (has-name-expired 
                                   (expects! (get namespace current-owned-name) (err err-panic))
                                   (expects! (get name current-owned-name) (err err-panic))))))
            (asserts!
              can-new-owner-get-name
              (err err-principal-already-associated))
            (expects!
              (nft-transfer! names
                            (tuple (name name) (namespace namespace))
                            tx-sender
                            owner-unwrapped) ;; todo(ludo): tx-sender or contract-caller?. Unwrap new-owner
              (err err-name-transfer-failed))
            (ok 'true)))))
        ;; Update the zonefile, if any.
    (if (is-none? zonefile-content)
      'false
      (map-set! zonefiles
        ((namespace namespace) (name name))
        ((updated-at block-height)
         (content (expects! zonefile-content (err err-panic))))))
    ;; Update the name's properties
    (map-set! name-properties
      ((namespace namespace) (name name))
      ((registered-at (some block-height))
       (imported-at none)
       (revoked-at none)))
    (ok 1)))

;;;; SPONSORED_NAME

;; SPONSORED_NAME_REGISTER_BATCH
;;(define-public sponsored-name-register-batch
;;  (err err-not-implemented))

;; SPONSORED_NAME_UPDATE
;;(define-public sponsored-name-update
;;  (err err-not-implemented))

;; SPONSORED_NAME_TRANSFER
;;(define-public sponsored-name-transfer
;;  (err err-not-implemented))

;; SPONSORED_NAME_REVOKE
;;(define-public sponsored-name-revoke
;;  (err err-not-implemented))
