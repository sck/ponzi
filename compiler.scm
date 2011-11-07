(define generated (make-string))

(define emit (lambda xs (for-each xs (lambda (s) (string-append! generated s)))))

(define *MOV-RCX-IMM* "\x48\xb9")
(define *CALL-RCX* "\xff\xd1")

(define asm-cfunc-call (lambda(cf)
  (emit *MOV-RCX-IMM* (cfunc->binary-addr-s cf))
  (emit *CALL-RCX*)))

(define *MOV-RDX-IMM* "\x48\xBA")
(define *MOV-RSI-IMM* "\x48\xBE")
(define *MOV-RDI-IMM* "\x48\xBF")

(define asm-cfunc-push-parameters (lambda (a8 b8 c8)
  (emit *MOV-RDX-IMM* (va->binary-addr-s c8))
  (emit *MOV-RSI-IMM* (va->binary-addr-s b8))
  (emit *MOV-RDX-IMM*  (va->binary-addr-s a8))))

(define *RET* "\xC3")
(define asm-return (lambda ()
  (emit *RET*)))

(define cfunc-to-bin-adr (make-hash))
(define bin-adr-to-cfunc (make-hash))

(hash-each globals (lambda (k v) 
    (if (cfunc? v) (begin 
      (hash-set! cfunc-to-bin-adr k (cfunc->binary-addr-s v)) 
      (hash-set! bin-adr-to-cfunc (cfunc->binary-addr-s v) k))
      #f)))

(define disassemble (lambda ()
  (do 
    ((s (string-copy generated)) 
     (i 0 (+ i 1)))
    ((< (string-length s) 1))
    (define start1 (substring s 0 1))
    (define start2 (substring s 0 2))
    (define skip 1)
    (displayln "s: " (string-length s) ", skip0: " skip)
    (eval-case start1
      (*RET* (displayln "RET!") (define skip 1)))
    (eval-case start2 
      (*MOV-RCX-IMM* (displayln "CALL: " skip) (set! skip 12)
          (displayln "skip now: " skip))
      (*MOV-RDX-IMM* (displayln "PARAMETERS") (set! skip 30)))
    (displayln "skip: " skip)
    (define s (substring s skip -1))
  )
))

(define compile (lambda (tokens)
  (case (type-of tokens)
    ('lambda (displayln "lambda: " tokens) (compile (list-ref tokens 1)))
    ('vector (displayln "vector: " tokens) 
      (define x0 (vector-shift! tokens))
      (case x0 
        ('quote (displayln "quote"))
        ('/# (displayln "/#"))
        ('if (displayln "if"))
        ('begin (displayln "begin") (vector-each tokens (lambda (x) (compile x))))
        (else 
            (define bin (hash-get cfunc-to-bin-adr x0))
            (if bin 
              (asm-cfunc-push-parameters )
              (displayln "unknown symbol:" x0))
            ))))))

(displayln "compiler loaded")
