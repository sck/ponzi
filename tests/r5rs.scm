#! ./ponzi 

(define t (lambda (v) (if (eq? v #t) #t (displayln "Error"))))
(define f (lambda (v) (if (eq? v #t) (displayln "Error") #t)))

(t (eq? #xa 10))
(t (eq? #b11 4))
(t (eq? #o33 4))
(t (eq? (string->number "100") 100))
(t (eq? (string->number "150.0") 150.0))
(t (boolean? #f))
(f (boolean? 0))
(f (boolean? '()))
(t (null? '()))

;(equal? (make-vector 3 0) '#(0 0 0))
;(equal? (make-vector 3 1) '#(1 1 1))

;(t (eq? (string->number "100" 16) 256))
;(t (eq? (string->number "1e2") 100))

