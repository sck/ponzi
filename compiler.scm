(define generated (make-string))

(define emit (lambda xs (for-each xs (lambda (s) (string-append! generated s)))))

(define *MOV-RCX-IMM* "\x48\xb9")
(define *CALL-RCX* "\xff\xd1")

(define asm-cfunc-call (lambda(cf)
  (emit *MOV-RCX-IMM* (cfunc->binary-addr-s cf))
  ; call rcx
  (emit *CALL-RCX*)))


(define *MOV-RDX-IMM* "\x48\xBA")

(define asm-cfunc-push-parameter (lambda (a8 b8 c8) 
  ; movabsq <c8>, %rdx
  (emit *MOV-RDX-IMM* (va->binary-addr-s c8))
  ; movabsq <b8>, %rsi
  (emit "\x48\xBE" (va->binary-addr-s b8))
  ;  movabsq <a8>, %rdi
  (emit "\x48\xBF"  (va->binary-addr-s a8))))

(define *RET* "\xC3")
(define asm-return (lambda ()
  ;ret
  (emit *RET*)))

(define disassemble (lambda () 
  (define s (string-copy generated))
  (define start1 (substring generated 0 1))
  (define start2 (substring generated 0 2))
  (eval-case start1
    (*RET* (displayln "RET!")))
  (eval-case start2 
    (*MOV-RCX-IMM* (displayln "CALL!"))
    (*MOV-RDX-IMM* (displayln "PARAMETERS")))
))

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
