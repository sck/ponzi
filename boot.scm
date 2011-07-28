(define puts (lambda (s) (begin (display s) (newline))))
(define int-times (lambda (n l m) 
  (begin 
    (l (- m n)) 
    (if (<= n 1) 0 (int-times (- n 1) l m)))))

(define times (lambda (n l) (int-times n l (+ n 1))))


