(define generated (make-string))

(define emit (lambda (s)
    (string-append! generated s)))

(define asm-cfunc-call (lambda(cf)
  ; movabs <cf>,%rdx
  (emit "\x48\xba" (cfunc->binary-addr cf)))
  ; callq *%rdx
  (emit "\xff\xd2"))

(define asm-cfunc-push-parameter (lambda (a8 b8 c8) 
  ; movabsq <c8>, %rdx
  (emit "\x00\x54\x48\xBA" (binary-addr c8))
  ; movabsq <b8>, %rsi
  (emit "\x00\x5e\x48\xBE" (binary-addr b8))
  ;  movabsq <a8>, %rdi
  (emit "\x00\x68\x48\xBF"  (binary-addr a8))))

(define asm-return (lambda ()
  ;ret
  (emit "\x00\x7d\xC3")))
  


(define compile (lambda (tokens)
  (case (type-of tokens)
    ('lambda (displayln "lambda: " tokens) (compile (list-ref tokens 1)))
    ('vector (displayln "vector: " tokens) 
      (define x0 (vector-unshift! tokens))
      (case x0 
        ('quote (displayln "quote"))
        ('/# (displayln "/#"))
        ('if (displayln "if"))
        ('begin (displayln "begin") (vector-each tokens (lambda (x) (compile x))))
        (else (displayln "unknown symbol: " x0)))))))

(displayln "compiler loaded")
