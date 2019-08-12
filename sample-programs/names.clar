(define-constant burn-address 'SP000000000000000000002Q6VF78)
(define-private (price-function (name int))
  (if (< name 100000) 1000 100))
         
(define-map name-map 
  ((name int)) ((owner principal)))
(define-map preorder-map
  ((name-hash (buff 20)))
  ((buyer principal) (paid int)))
         
(define-public (preorder 
                (name-hash (buff 20))
                (name-price int))
  (if (is-ok? (contract-call! tokens token-transfer
                burn-address name-price))
      (begin (insert-entry! preorder-map
                     (tuple (name-hash name-hash))
                     (tuple (paid name-price)
                            (buyer tx-sender)))
             (ok 0))
      (err "token payment failed.")))

(define-public (register 
                (recipient-principal principal)
                (name int)
                (salt int))
  (let ((preorder-entry
         (expects! ;; name _must_ have been preordered.
           (fetch-entry preorder-map
                      (tuple (name-hash (hash160 (xor name salt)))))
           (err "no preorder found")))
        (name-entry 
         (fetch-entry name-map (tuple (name name)))))
    (if (and
         ;; name shouldn't *already* exist
         (is-none? name-entry)
         ;; preorder must have paid enough
         (<= (price-function name) 
             (get paid preorder-entry))
         ;; preorder must have been the current principal
         (eq? tx-sender
              (get buyer preorder-entry)))
        (if (and
              (insert-entry! name-map
                        (tuple (name name))
                        (tuple (owner recipient-principal)))
              (delete-entry! preorder-map
                        (tuple (name-hash (hash160 (xor name salt))))))
            (ok 0)
            (err "failed to insert new name entry"))
        (err "invalid name register"))))
