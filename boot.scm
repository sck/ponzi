(define first car)
(define rest cdr)
(define for-each vector-each)
(define find vector-find)
(define list-ref vector-get)
(define length vector-length)
(define list-tail vector-tail)
(define append vector-append)
(define odd? (lambda (n) (eq? (& n 1) 1)))
(define even? (lambda (n) (eq? (& n 1) 0)))
(define zero? (lambda (n) (eq? n 0)))
(define any? (lambda (l v) 
    (define rany #f)
    (find l (lambda (x) (if (eq? x v) (begin (set! rany #t) #t) #f)))
    rany))

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
      (vector-each bindings (lambda (v) 
          (vector-push! a (list 'define (list-ref v 0) (eval (list-ref v 1)))))) 
      a))
    (eval (append '(begin) (list-tail xs 1)))))

(define let let*)

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

(define int-times (lambda (n l m) 
    (l (- m n)) 
    (if (<= n 1) 0 (int-times (- n 1) l m))))

(define times (lambda (n l) (int-times n l (+ n 1))))

(define vector-map (lambda (vector l) 
    (define a (make-vector)) 
    (vector-each vector (lambda (x) 
      (vector-push! a (l x)))) 
   a))

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


;(load "compiler.scm")
