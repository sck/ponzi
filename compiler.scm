(define generated (make-string))

(define emit (lambda xs (for-each xs (lambda (s) (string-append! generated s)))))

(define asm-cfunc-call (lambda(cf)
  ; mov rcx,0x100000983
  (emit "\x48\xb9" (cfunc->binary-addr-s cf)))
  ; call rcx
  (emit "\xff\xd1")
  (displayln "hmmm..."))

(define asm-cfunc-push-parameter (lambda (a8 b8 c8) 
  ; movabsq <c8>, %rdx
  (emit "\x48\xBA" (va->binary-addr-s c8))
  ; movabsq <b8>, %rsi
  (emit "\x48\xBE" (va->binary-addr-s b8))
  ;  movabsq <a8>, %rdi
  (emit "\x48\xBF"  (va->binary-addr-s a8))))

(define asm-return (lambda ()
  ;ret
  (emit "\xC3")))

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
