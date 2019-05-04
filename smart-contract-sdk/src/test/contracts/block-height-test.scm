(define-map height-info ((key int)) ((height int)))

(define (get-height-info (key int))
    (let 
        ((height (get height 
            (fetch-entry height-info (tuple (key key))))))
        (if (eq? height 'null) 0 height)))

(define (get-current-block-height)
  (begin block-height))

(define height-at-deployment block-height)

(begin
    (set-entry! height-info 
        (tuple (key 123))
        (tuple (height block-height)))
    'null)
