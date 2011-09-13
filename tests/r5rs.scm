#! ./ponzi 

(define describe (lambda-no-parameter-eval xs
  (define what (eval (first xs)))
  (define supports (lambda-no-parameter-eval xs
    (define message (eval (first xs)))
    (define t (lambda-no-parameter-eval (v) (define r (eval v)) (if (eq? r #t) #t (displayln "Error: `" v "' => " r))))
    (define f (lambda-no-parameter-eval (v) (define r (eval v)) (if (eq? r #t) (displayln "Error: `" v "' => " r) #t)))
    (define t-eq (lambda-no-parameter-eval (a0 b0) (define a (eval a0)) (define b (eval b0)) (if (equal? a b) #t (displayln "Error: `" a0 "' expected to be: => " b0 ", but was: " a))))
    (displayln "  - " message)
    (eval (append '(begin) (list-tail xs 1)))))
  (define no-crash-when (lambda-no-parameter-eval xs
    (define message (eval (first xs)))
    (displayln "  - " message)
    (eval (append '(begin) (list-tail xs 1)))))
  (displayln what)
  (eval (append '(begin) (list-tail xs 1)))
  (displayln)))

(describe "parser"
  (supports "new-lines after )")
)

(describe "ponzi"
  (supports "proper scoping" 
    (define foo 1)
    (set! foo 2)
    (t-eq foo 2)
    (define func (lambda () (set! foo 3)))
    (func)
    (t-eq foo 3))
  (supports "tail recursion optimization" 
    (define n 3)
    (define tail-rc (lambda () 
      (if (> n 1) (begin (set! n (- n 1)) (tail-rc)) #f)))
    (t-eq n 3)
    (tail-rc)
    (t-eq n 1)
  )
  (supports "times" 
    (times 2 (lambda (n) 0)))
  (supports "floating-point numbers" 
    (t (< (- (+ 2.0 3.0) 5.0) 0.001)))
  (supports "\\x00 in strings"
    (t-eq "\x00" "\x00")
    (f (eq? "\x00\x01" "\x00\x02")))
  (supports "in-string quotations"
    (t-eq (string-append "test" #\newline #\return #\xff "88" ) "test\n\r\xff88"))
  (supports "substrings"
    (t-eq (substring "test" -2 1) "t")
    (t-eq (substring "test" 0 -2) "tes")
    (t-eq (substring "test" 1 -2) "es"))
)

(describe "r5rs implementation"
  (supports "define"
    (define a 1)
    (define a 2))
  (supports "#b #x #o formatted number literals"
    (t-eq #xa 10)
    (t-eq #b11 3)
    (t-eq #o33 27))
  (supports "number tests"
    (t (zero? 0))
    (t (odd? 1))
    (f (even? 1)))
  (supports "string->number"
    (t-eq (string->number "100") 100)
    (t-eq (string->number "150.0") 150.0))
  (supports "string type conversion"
    (t-eq (string->number "100") 100)
    (t-eq (string->number "150.0") 150.0)
    (t (symbol? (string->symbol "test")))
    (t (string? (symbol->string 'test))))
  (supports "number->string"
    (t-eq (number->string 16 16) "#x10"))
  (supports "type querying"
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
    (f (string? 0))
    (t (string? "foo")))
  (supports "equality"
    (t (equal? (list 1 2 3 4 5) (list 1 2 3 4 5)))
    (t-eq 'foo 'foo)
    (t-eq '() '()))
  (supports "string operations"
    (t-eq (string-append "1" "2") "12")
    (t-eq (string-append "1" "2") "12")
    (t-eq (substring "test" 1 2) "es")
    (string-copy "foo"))
  (supports "list operations"
    (t-eq (length (list 1 2 3)) 3)
    (t-eq (list-ref (list 1 2 3) 1) 2)
    (t-eq (first (list 1 2)) 1)
    (t-eq (rest (list 1 2 3)) (list 2 3))
    (t-eq (append (list 1 2) (list 3 4)) (list 1 2 3 4)))
  (supports "cond"
    (t-eq (cond ((> 3 2) 'something 'greater) ((< 3 2) 'smaller)) 'greater)
    (t-eq (cond ((> 2 3) 'greater) ((< 1 2) 'something 'smaller)) 'smaller)
    (t-eq (cond ((> 2 3) 'greater) ((< 2 2) 'smaller) (else 'not 'nothing)) 'nothing))
  (supports "case"
    (t-eq (case (* 2 3)
      ((2 3 5 7) 'test 'prime)
      ((1 4 6 8 9) 'test 'composite)) 'composite)
    (t-eq (case 'foo ('foo 'works) ((else) 'not-working)) 'works)
    (t-eq (case "works?" ("works?" 'works) ((else) "NO")) 'works))
  (supports "let*/let"
    (t-eq (let* ((a 1) (b (* 2 3))) b) 6)
    (t-eq (let ((a 1) (b (* 2 3))) b) 6))

  (displayln "  - load"))
(load "does-not-exist.scm")
(load "./tests/r5rs-load.scm")

(describe "doesn't crash when"
  (no-crash-when "redefining a lambda"
    (define a (lambda () (* 1 2)))
    (define a (list-ref a 1)))
)

(begin (define a (lambda () (* 1 2))) (define a (list-ref a 1)))

;;(equal? (make-vector 3 0) '#(0 0 0))
;;(equal? (make-vector 3 1) '#(1 1 1))
;
;;(t (eq? (string->number "100" 16) 256))
;;(t (eq? (string->number "1e2") 100))

