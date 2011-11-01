#! ./ponzi 

;(m 200_000 (lambda (n) (display n) (resetline)))

;(m 1 (lambda (t) (do ((i 0 (+ i 1))) ((= i 200_000)) (display i) (resetline) ) ))
(m 1 (lambda (t) (do ((i 0 (+ i 1))) ((= i 200_000)) #t)))

;(do ((i 0 (+ i 1))) ((= i 5000) #t) (display i) (resetline))

;(m 200_000 (lambda (n) 0))
;(m 2 (lambda (n) (puts n)))
;(m 2000 (lambda (n) 0))
