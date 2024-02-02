(define-map int-to-int int int)

(define-private (insert (val int) (x int))
  (begin
    (map-insert int-to-int val val)
    x
  )
)

(define-public (insert-list (l (list 16384 int)))
  (ok (fold insert l 0))
)


(define-read-only (get-one (key int))
  (map-get? int-to-int key)
)