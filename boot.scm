(define p inspect)
(define find vector-find)
(define or (lambda-no-parameter-eval xs 
    (define ror #f) (find xs (lambda (v) (if (eval v) (set! ror #t) #f))) ror))
(define and (lambda-no-parameter-eval xs 
    (define rand #t) (find xs (lambda (v) (if (eval v) #f (begin (set!  rand #f) #t))))
    rand))
(define first car)
(define rest cdr)
(define for-each vector-each)
(define list-ref vector-get)
(define length vector-length)
(define list-tail vector-tail)
(define append vector-append)
(define odd? (lambda (n) (eq? (& n 1) 1)))
(define even? (lambda (n) (eq? (& n 1) 0)))
(define zero? (lambda (n) (eq? n 0)))
(define any? (lambda (l v) 
    (define rany #f)
    (find l (lambda (x) (if (eq? x v) (set! rany #t) #f))) rany))

;
(define char? (lambda (w) (eq? (type-of w) 'char)))
(define string? (lambda (w) (eq? (type-of w) 'string)))
(define list? (lambda (w) (eq? (type-of w) 'vector)))
(define symbol? (lambda (w) (eq? (type-of w) 'symbol)))
(define boolean? (lambda (w) (eq? (type-of w) 'bool)))

(define procedure? (lambda (w) 
    (define t (type-of w)) (or (eq? t 'cfunc) (eq? t 'lambda))))
(define lambda? (lambda (w) (define t (type-of w)) (eq? t 'lambda)))
(define cfunc? (lambda (w) (define t (type-of w)) (eq? t 'cfunc)))
(define null? (lambda (w) (eq? w '())))


(define newline (lambda () (display #\newline)))
(define resetline (lambda () (display #\return)))

(define displayln (lambda xs (for-each xs display) (newline)))
(define #hash (lambda xs 
    (define h (make-hash)) 
    (vector-each xs (lambda (v) (hash-set! h (car v) (cdr v))))
    h))

(define let* (lambda-no-parameter-eval xs
    (define bindings (first xs))
    (eval (begin 
      (define a (make-vector)) 
      (vector-push! a 'begin)
      (for-each bindings (lambda (v) 
          (vector-push! a (list 'define (list-ref v 0) (eval (list-ref v 1))))))
      a))
    (eval (append '(begin) (list-tail xs 1)))))
(define let let*)


(define do (lambda-no-parameter-eval xs
    (if (= (length xs) 1) 
      (begin 
        (if (eval test-condition) (eval test-conseq) 
          (begin 
            (eval body)
            (eval after-each-step)
            (do 1)
          ))
      )
      (begin 
        (define init0 (first xs))
        (define test0 (list-ref xs 1))
        (define body (append '(begin) (list-tail xs 2)))
        (define inits (append '(begin) '()))
        (define after-each-step (append '(begin) '()))
        (for-each init0 (lambda (i) 
          (define name (first i))
          (define value (list-ref i 1))
          (define step (list-ref i 2))
          (vector-push! inits (list 'define name value))
          (if step (vector-push! after-each-step (list 'define name step)) #f)
        ))
        (eval inits)
        (define test-condition (first test0))
        (define test-conseq (append '(begin) (list-tail test0 1)))
        (do 1)
      ))
))

(define cond (lambda-no-parameter-eval xs
    (define rcond #f)
    (find xs (lambda (x)
        (define t (first x))
        (if (or (eq? t 'else) (eval t))
            (begin (set! rcond (eval (append '(begin) (list-tail x 1)))) #t)
            #f)))
    rcond))

(define case (lambda-no-parameter-eval xs
    (define rcase #f)
    (define value (eval (first xs)))
    (find (list-tail xs 1) (lambda (x)
        (define list (first x))
        (if (or (eq? list 'else) (any? list value))
            (begin (set! rcase (eval (append '(begin) (list-tail x 1)))) #t)
            #f)))
    rcase))

(define eval-case (lambda-no-parameter-eval xs
    (define rcase #f)
    (define value (eval (first xs)))
    (find (list-tail xs 1) (lambda (x)
        (define list (eval (first x)))
        (if (or (eq? list 'else) (eq? list value))
            (begin (set! rcase (eval (append '(begin) (list-tail x 1)))) #t)
            #f)))
    rcase))

(define int-times (lambda (n l m)
    (l (- m n)) 
    (if (<= n 1) 0 (int-times (- n 1) l m))))

(define times (lambda (n l) (int-times n l (+ n 1))))

(define vector-map (lambda (vector l) 
    (define a (make-vector)) 
    (vector-each vector (lambda (x) 
      (vector-push! a (l x)))) 
   a))

(define map vector-map)

(define vector-grep (lambda (vector rx)
  (define a (make-vector))
  (vector-each vector (lambda (v)
    (if (rx-match-string rx v) (vector-push! a v) 0)))
  a))

(define fib-memo (make-hash))
(define fib (lambda (n) (if (hash-get fib-memo n) (hash-get fib-memo n) (hash-set! fib-memo n (if (< n 2) n (+ (fib (- n 1)) (fib (- n 2))))))))

(define m (lambda (n l) 
  (set! before (current-ms)) 
  (times n l) 
  (newline)
  (display (- (current-ms) before)) 
  (displayln (quote ms))))

(define reload (lambda () (load "boot.scm")))

(load "compiler.scm")

(define mv (lambda () (define a (make-vector)) (vector-push! a 'foo) a))
