(define burn-address 'SP000000000000000000002Q6VF78)
(define (price-function (name int))
  (if (< name 100000) 1000 100))
         
(define-map name-map 
  ((name int)) ((owner principal)))
(define-map preorder-map
  ((name-hash (buff 20)))
  ((buyer principal) (paid int)))
         
(define-public (preorder 
                (name-hash (buff 20))
                (name-price int))
  (if (contract-call! tokens token-transfer
                      burn-address name-price)
      (insert-entry! preorder-map
                     (tuple (name-hash name-hash))
                     (tuple (paid name-price)
                            (buyer tx-sender)))
      'false))

(define-public (register 
                (recipient-principal principal)
                (name int)
                (salt int))
  (let ((preorder-entry
         (fetch-entry preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
        (name-entry 
         (fetch-entry name-map (tuple (name name)))))
    (if (and
         ;; must be preordered
         (not (eq? preorder-entry 'null))
         ;; name shouldn't *already* exist
         (eq? name-entry 'null)
         ;; preorder must have paid enough
         (<= (price-function name) 
             (get paid preorder-entry))
         ;; preorder must have been the current principal
         (eq? tx-sender
              (get buyer preorder-entry)))
        (and
         (insert-entry! name-map
                        (tuple (name name))
                        (tuple (owner recipient-principal)))
         (delete-entry! preorder-map
                        (tuple (name-hash (hash160 (xor name salt))))))
        'false)))
