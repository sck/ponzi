(displayln "compiler loaded")

(define compile (lambda tokens 
  (case (type-of tokens)
    ('lambda (displayln "lambda") (compile (list-ref tokens 1)))
    ('vector (displayln "vector" tokens) (vector-each tokens 
        (lambda (xt) (displayln "xt:" xt))))
    ('symbol (displayln "symbol")))))

