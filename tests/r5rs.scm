#! ./ponzi 

(define t (lambda-no-parameter-eval (v) (define r (eval v)) (if (eq? r #t) #t (displayln "Error: `" v "' => " r))))
(define f (lambda-no-parameter-eval (v) (define r (eval v)) (if (eq? r #t) (displayln "Error: `" v "' => " r) #t)))

(t (eq? #xa 10))
(t (eq? #b11 3))
(t (eq? #o33 27))
(t (eq? (string->number "100") 100))
(t (eq? (string->number "150.0") 150.0))
(t (symbol? (string->symbol "test")))
(t (boolean? #f))
(f (boolean? 0))
(f (boolean? '()))
(t (null? '()))

(t (procedure? car))
(f (procedure? 'car))
(t (procedure? (lambda (x) (* x x))))
(f (procedure? '(lambda (x) (* x x))))

(t (list? (list 1 2 3)))
(t (list? '()))
(f (list? 0))

(f (load "does-not-exist.scm"))
;(t (begin (load "./tests/r5rs-load.scm") r5rs-loaded))

(t (eq? (string-append "1" "2") "12"))
(t (eq? (string-append "1" "2") "12"))
(string-copy "foo")

(t (eq? (cond ((> 3 2) 'greater) ((< 3 2) 'smaller)) 'greater))
(t (eq? (cond ((> 2 3) 'greater) ((< 1 2) 'smaller)) 'smaller))
(t (eq? (cond ((> 2 3) 'greater) ((< 2 2) 'smaller) (else 'nothing)) 'nothing))

(t (eq? (length (list 1 2 3)) 3))
(t (eq? (list-ref (list 1 2 3) 1) 2))
(t (eq? (find (list 2 2 3 4) odd?) 3))
(t (eq? (first (list 1 2)) 1))
;(t (eq? (rest (list 1 2 3)) (list 2 3)))
(t (zero? 0))

(t (eq? (case (* 2 3)
  ((2 3 5 7) 'prime)
  ((1 4 6 8 9) 'composite)) 'composite))


;(t (begin (define s (make-string)) ((eq? (string-copy "1")

;(load "foo.scm")

;(equal? (make-vector 3 0) '#(0 0 0))
;(equal? (make-vector 3 1) '#(1 1 1))

;(t (eq? (string->number "100" 16) 256))
;(t (eq? (string->number "1e2") 100))

