#! ./schemejit 

(define m (lambda (n l) 
  (begin 
    (set! before (current-ms)) 
    (times n l) 
    (newline)
    (display (- (current-ms) before)) 
    (puts (quote ms)))))

(m 5_000 (lambda (n) (begin (display n) (resetline))))
;(m 2 (lambda (n) (begin (puts n))))
;(m 2000 (lambda (n) 0))
