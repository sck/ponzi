(define puts (lambda xs (array-each xs display) (newline)))
(define #hash (lambda xs 
    (define h (make-hash)) 
    (array-each xs (lambda (v) (hash-set h (car v) (cdr v))))
    h))
(define first car)
(define last cdr)

(define int-times (lambda (n l m) 
    (l (- m n)) 
    (if (<= n 1) 0 (int-times (- n 1) l m))))

(define times (lambda (n l) (int-times n l (+ n 1))))

(define array-map (lambda (array l) 
    (define a (make-array)) 
    (array-each array (lambda (x) 
      (array-push a (l x)))) 
   a))

(define array-grep (lambda (array rx)
  (define a (make-array))
  (array-each array (lambda (v)
    (if (rx-match-string rx v) (array-push a v) 0)))
  a))

(define test-parallel-write (lambda (n) 
  (times n (lambda (n) (hash-set h (rand 20) (rand 20))))))

(define tpw test-parallel-write)
