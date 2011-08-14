(define displayln (lambda xs (vector-each xs display) (newline)))
(define #hash (lambda xs 
    (define h (make-hash)) 
    (vector-each xs (lambda (v) (hash-set! h (car v) (cdr v))))
    h))
(define first car)
(define rest cdr)

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

(define test-parallel-write (lambda (n) 
  (times n (lambda (n) (hash-set! h (rand 20) (rand 20))))))

(define tpw test-parallel-write)

(define fib-memo (make-hash))
(define fib (lambda (n) (if (hash-get fib-memo n) (hash-get fib-memo n) (hash-set! fib-memo n (if (< n 2) n (+ (fib (- n 1)) (fib (- n 2))))))))

(define m (lambda (n l) 
  (begin 
    (set! before (current-ms)) 
    (times n l) 
    (newline)
    (display (- (current-ms) before)) 
    (displayln (quote ms)))))

