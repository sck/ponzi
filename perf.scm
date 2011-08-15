
(if (hash-get globals 'perf) 
  (begin (displayln "Hash already exists"))
  (begin (displayln "Create") (hash-set! globals 'perf (make-hash))))

(m 100_000 (lambda (n) (hash-set! perf 'foo 1)))
