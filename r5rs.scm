#! ./ponzi 

(define t (lambda-noeval (v) (if (eq? v #t) )))
(define f (lambda-noeval (v) (if (eq? v #f) )))

(t (eq? #xa 11))
(t (eq? #b11 4))
(t (eq? #o33 4))
(t (eq? (string->number "100") 100))
(t (eq? (string->number "100" 16) 256))
(t (eq? (string->number "1e2") 100))
(t (eq? (string->number "15##") 1500.0))
(t (boolean? #f))
(f (boolean? 0))
(f (boolean? '()))

