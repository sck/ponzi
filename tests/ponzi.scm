#! ./ponzi 

(define t (lambda (v) (if (eq? v #t) #t (displayln "Error"))))
(define f (lambda (v) (if (eq? v #t) (displayln "Error") #t)))

(eq? (list 1 2 3) (list 1 2 3))
(t (eq? (eval '(list 1 2 3)) (list 1 2 3)))
t

(t (any? (list 1 2 4 'a 10) 'a))
(f (any? (list 1 2 4 'a 10) 'f))
(t (eq? (list-tail (list 1 2 3) 1) (list 2 3)))

(t-eq (first (list 1 2)) 1)
(t-eq (find (list 2 2 3 4) odd?) 3)
