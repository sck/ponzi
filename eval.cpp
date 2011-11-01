/*
 * Copyright (c) 2010, 2011, Sven C. Koehler
 */


#define pz_should_not_reach_here()  \
  fprintf(stderr, "Should not reach here\n"); abort();

Id pz_to_string(void *b, Id exp);

#define VB void *b, Id x, pz_interp_t *pi, pz_stack_frame_t *sf

#define pz_handle_parse_error_with_err_string_nh(m,ln) \
    __pz_handle_parse_error_with_err_string(__func__, b, m, 0, ln, pi->ps)
#define pz_handle_parse_error_with_err_string(m, h) \
    __pz_handle_parse_error_with_err_string(__func__, b, m, h, \
    pz_ary_get_line_number(b, x), pi->ps)
Id __pz_handle_parse_error_with_err_string(const char *w, void *b, 
    const char *error_msg, const char *h, int ln, pz_parse_t *ps) { 
  char es[1024]; 
  snprintf(es, 1023, "%s:%d: %s", pz_string_ptr(ps->filename), ln, error_msg);
  return pz_handle_error_with_err_string(w, es, h); 
}

#define NVB void *b, Id x, pz_interp_t *pi, pz_stack_frame_t *sf
#define NVP b, x, pi, sf
Id pz_e_exec_procedure(void *b, Id x, pz_interp_t *pi, Id func_name = pzNil, 
    Id env = pzNil);
Id pz_dispatch(void *b, Id x, pz_interp_t* pi, pz_stack_frame_t *sf);
Id pz_begin(NVB, int start);
Id pz_lambda(void *b, Id x, Id env);

#define PZ_ED(name,block) \
Id pz_e_##name(NVB) { \
  Id env = sf->env; env = env; \
  block \
}

#define pz_e(x,last) __pz_e(b, x, pi, sf, last)

Id __pz_e(void *b, Id x, pz_interp_t* pi, pz_stack_frame_t *sf, int last) {
  sf->last = last; 
  return pz_dispatch(b, x, pi, sf);
}

PZ_ED(globals, { return pz_globals; })
PZ_ED(vars, { return pz_retain(sf->func_name, env); })
PZ_ED(string_interns, { return pz_string_interns; })
PZ_ED(symbol_interns, { return pz_symbol_interns; })
PZ_ED(string_constants, { return pz_string_constants; })
PZ_ED(string_constants_dict, { return pz_string_constants_dict; })
PZ_ED(xtrue, { return pzTrue; })
PZ_ED(xfalse, { return pzNil; })
PZ_ED(env_find, { return pz_env_find(b, env, x); })
PZ_ED(literal, { return x; })
PZ_ED(cons_pair, {
  Id a = pz_ary_new(b);
  pz_ary_push(b, a, pz_e(ca_f(x), 0));
  pz_ary_push(b, a, pz_e(ca_th(x), 1));
  return a;
})
PZ_ED(quote, { return ca_s(x); })
PZ_ED(rx, { 
  Id rx = pz_rx_new(pz_ary_join_by_s(b,  
      pz_ary_clone_part(b, x, 1, -1), IS(" ")));
  return rx;
}) 
PZ_ED(xif, {
  Id test = ca_s(x); Id conseq = ca_th(x); Id alt = ca_fth(x);
  Id t = pz_e(test, 0);
  return cnil2(b, t) ? pz_e(conseq, 1) : pz_e(alt, 1);
})
PZ_ED(set_bang, {
  Id var = ca_s(x); Id exp = ca_th(x);
  return pz_env_find_and_set(b, env, var, pz_e(exp, 0));
})
PZ_ED(define, {
  Id var = ca_s(x); Id exp = ca_th(x);
  return pz_ht_set(b, env, var, pz_e(exp, 1));
})
PZ_ED(lambda, { return pz_lambda(b, x, env); })
PZ_ED(macro, { Id l = pz_lambda(b, x, env); pz_ary_set_macro(b, l); return l; })
PZ_ED(begin, { return pz_begin(NVP, 1); })
PZ_ED(proc, {
  RG(gv);
  Id func_name = ca_f(x);
  Id lambda = pz_env_find(b, env, func_name);
  if (!lambda) { 
    RG(sg);
    return pz_handle_parse_error_with_err_string("Unknown proc", 
        pz_string_ptr(sg = pz_to_string(b, func_name)));
  }
  int is_cfunc = pz_is_type_i(lambda, PZ_TYPE_CFUNC);
  int no_parameter_eval = !is_cfunc && pz_ary_is_macro(b, lambda);

  Id vars = gv = pz_ary_new(b); Id v; int i = 1;
  while (pz_ary_iterate(b, x, &i, &v))
      pz_ary_push(b, vars, no_parameter_eval ? v : pz_e(v, 0));
  if (is_cfunc) return pz_call(b, lambda, vars, pi, sf);
  int tail_rc = 0;
  int is_tail_call = pz_eq_i(func_name, sf->func_name);
  if (is_tail_call) tail_rc = sf->last;
  RG(eg);
  Id e = tail_rc ? env : (eg = pz_env_new(b, 
      no_parameter_eval ? env : lambda_env_ctx(lambda))); Id p;
  Id vdecl = lambda_vdecl(lambda);
  if (PZ_TYPE(vdecl) == PZ_TYPE_ARRAY) {
    if (pz_ary_len(b, vdecl) != pz_ary_len(b, vars))  {
       char es[1024]; 
       snprintf(es, 1023, "Parameter count mismatch! (have %d, expected %d)", 
           pz_ary_len(b, vars), pz_ary_len(b, vdecl));  
       return pz_handle_parse_error_with_err_string(es, 
           pz_string_ptr(func_name));
    }
    i = 0;
    while (pz_ary_iterate(b, vdecl, &i, &p)) 
        pz_ht_set(b, e, p, pz_ary_index(b, vars, i - 1));
  } else {
    pz_ht_set(b, e, vdecl, vars);
  }
  if (tail_rc) return pzTail;
  return pz_e_exec_procedure(b, lambda_body(lambda), pi, func_name, e);
})

// ...

class ScopeGuard {
  void *b;
  Id env;
public:
  ScopeGuard(void *_b, Id _env) : b(_b), env(_env) { pz_retain0(env); }
  ~ScopeGuard() { pz_release(env); }
};

#define PZ_CURRENT_STACK_FRAME &pi->frames[pi->nested_depth - 1]

Id pz_e_stack_frame(void *b, Id x, pz_interp_t *pi, Id env) {
  if (pi->stack_overflow) return pzNil;
  if (pi->nested_depth >= PZ_MAX_STACK) {
    pi->stack_overflow = 1;
    return pz_handle_parse_error_with_err_string("Stack overflow", ""); 
  }
  pi->nested_depth++;
  pz_stack_frame_t *sf = PZ_CURRENT_STACK_FRAME;
  memset(sf, 0, sizeof(pz_stack_frame_t));
  sf->env = env ? env : pz_globals;
  if (pi->nested_depth > 1) {
    pz_stack_frame_t *psf = &pi->frames[pi->nested_depth - 2];
    sf->func_name = psf->func_name;
  }
  return pzTrue;
}

Id pz_e_exec_procedure(void *b, Id x, pz_interp_t *pi, Id func_name, Id env) {
  ScopeGuard g(b, env);
  // create new stack frame
  if (!pz_e_stack_frame(b, x, pi, env)) return pzNil;
  pz_stack_frame_t *sf = PZ_CURRENT_STACK_FRAME;
  sf->x = x;
  sf->func_name = func_name;
tail_rc_start:
  Id rv = pz_dispatch(b, x, pi, PZ_CURRENT_STACK_FRAME);
  if (rv == pzTail) { 
    // env will already have been prepared by pz_e_proc
    goto tail_rc_start; 
  }
  // XXX: Mark for return, adjust REPL!
  pz_gc_mark_return_value(b, rv);
  pi->nested_depth--;
  return rv;
}

Id pz_begin(NVB, int start) {
  if (!pz_e_stack_frame(b, x, pi, sf->env)) return pzNil;
  pz_stack_frame_t *_sf = PZ_CURRENT_STACK_FRAME;
  _sf->x = x;
  Id val = pzNil, exp;
  int i = start;
  int l = pz_ary_len(b, x);
  while (pz_ary_iterate(b, x, &i, &exp)) {
    _sf->last = l == i;
    val = pz_dispatch(b, exp, pi, _sf);
  }
  pi->nested_depth--;
  return val;
}

Id pz_dispatch(void *b, Id x, pz_interp_t* pi, pz_stack_frame_t *sf) {
  // XXX: ask: have compiled version?
  if (!x) return pzNil;
  if (PZ_TYPE(x) == PZ_TYPE_SYMBOL) {
    if (pz_string_equals_cp_i(x, "globals")) return pz_e_globals(NVP);
    if (pz_string_equals_cp_i(x, "vars")) return pz_e_vars(NVP);
    if (pz_string_equals_cp_i(x, "string-interns")) 
        return pz_e_string_interns(NVP);
    if (pz_string_equals_cp_i(x, "symbol-interns")) 
        return pz_e_symbol_interns(NVP);
    if (pz_string_equals_cp_i(x, "string-constants")) 
        return pz_e_string_constants(NVP);
    if (pz_string_equals_cp_i(x, "string-constants-dict")) 
        return pz_e_string_constants_dict(NVP);
    if (pz_string_equals_cp_i(x, "#t")) return pz_e_xtrue(NVP);
    if (pz_string_equals_cp_i(x, "#f")) return pz_e_xfalse(NVP);
    return pz_e_env_find(NVP);
  } else if (PZ_TYPE(x) != PZ_TYPE_ARRAY) return pz_e_literal(NVP);
  if (PZ_TYPE(x) == PZ_TYPE_ARRAY && pz_ary_len(b, x) == 3) {
    Id m = ca_s(x);
    if (PZ_TYPE(m) == PZ_TYPE_SYMBOL && pz_string_equals_cp_i(m, ".")) 
        return pz_e_cons_pair(NVP);
  }
  if (pz_ary_len(b, x) == 0) {
    RG(sg);
    return pz_handle_parse_error_with_err_string("No proc given", 
        pz_string_ptr(sg = pz_to_string(b, sf->func_name))); 
  }
  Id x0 = ca_f(x);
  if (!pz_is_string(x0)) {
    RG(sg);
    return pz_handle_parse_error_with_err_string("Not a symbol type", 
        pz_string_ptr(sg = pz_to_string(b, sf->func_name)));
  }
  if (pz_string_equals_cp_i(x0, "quote")) {
    return pz_e_quote(NVP);
  } else if (pz_string_equals_cp_i(x0, "/#")) { // (/# ^regexp$)
    return pz_e_rx(NVP);
  } else if (pz_string_equals_cp_i(x0, "if")) { // (if test conseq alt)
    return pz_e_xif(NVP);
  } else if (pz_string_equals_cp_i(x0, "set!")) { // (set! var exp)
    return pz_e_set_bang(NVP);
  } else if (pz_string_equals_cp_i(x0, "define")) { // (define var exp)
    return pz_e_define(NVP);
  } else if (pz_string_equals_cp_i(x0, "lambda")) { //(lambda (var*) exp)
    return pz_e_lambda(NVP);
  } else if (pz_string_equals_cp_i(x0, "macro")) {
    return pz_e_macro(NVP);
  } else if (pz_string_equals_cp_i(x0, "begin")) {  // (begin exp*)
    return pz_e_begin(NVP);
  } else {  // (proc exp*)
    return pz_e_proc(NVP);
  }
  pz_should_not_reach_here();
}

Id __pz_vector_find(NVB, int check_brk = 1) {
  RG(sg);
  Id e = sg = pz_env_new(b, sf->env);
  Id lambda = ca_s(x);
  Id vdecl, pn = 0;
  int l;
  if (!pz_is_type_i(lambda, PZ_TYPE_CFUNC)) {
    vdecl = ca_f(lambda);
    l = pz_ary_len(b, vdecl);
    pn = l > 0 ? ca_f(vdecl) : pzNil;
  }
  int i = 0; 
  Id v;
  Id brk = pzNil;
  if (!pz_e_stack_frame(b, x, pi, sf->env)) return pzNil;
  pz_stack_frame_t *_sf = PZ_CURRENT_STACK_FRAME;
  _sf->x = x;
  _sf->env = e;
  Id vec = ca_f(x);
  while ((!check_brk || (check_brk && !brk)) && 
      pz_ary_iterate(b, vec, &i, &v)) {
    if (pz_is_type_i(lambda, PZ_TYPE_CFUNC)) {
      Id vars = pz_retain0(pz_ary_new(b));
      pz_ary_push(b, vars, v);
      brk = pz_call(b, lambda, vars, pi, _sf);
      pz_release(vars);
    } else {
      if (pn) pz_ht_set(b, e, pn, v);
      brk = pz_dispatch(b, lambda_body(lambda), pi, _sf);
    }
  }
  pi->nested_depth--;
  return check_brk ? v : pzNil;
}



Id pz_string_parse(void *b, Id s) {
  if (!s) return pzNil;
  Id ary = pz_retain0(pz_string_split(b, s, '"'));
  if (!ary) return pzNil;
  int string_mode = 0;
  Id v;
  int i = 0;
  Id r = pz_retain0(pz_ary_new(b));
  while (pz_ary_iterate(b, ary, &i, &v)) {
    if (!string_mode) {
      pz_ary_push(b, r, v);
    } else {
      int i = pz_register_string_constant(b, pz_string_unquote(b, v));
      //int i = pz_register_string_constant(b, v);
      Id sr = S("(string-constant ");
      pz_string_append(b, sr, pz_string_new_number(b, pz_long(i)));
      pz_string_append(b, sr, IS(")"));
      pz_ary_push(b, r, pz_intern(sr));
    }
    string_mode = 1 - string_mode;
  }
  pz_release(ary);
  Id rr = pz_ary_join_by_s(b, r, IS(""));
  pz_release(r);
  return rr;
}

Id pz_tokenize(void *b, Id va_s) {
  if (!va_s) return pzNil;
  RetainGuard0(va_s);
  Id r = pz_string_split(b,
      (pz_string_replace(b, 
        (pz_string_replace(b, 
          (pz_string_replace(b, va_s, 
            IS("\n"), IS(" \n "))),
        IS("("), IS(" ( "))), 
      IS(")"), IS(" ) "))), ' ');
  return r;
}

int pz_process_number(char *result, char *source) {
  size_t n = strlen(source);
  int base = 10;
  if (n > 1023) { n = 1023; }
  const char *s = source;
  char *d = result;
  char ch;
  if (n > 1 && s[0] == '-') {
    *d = s[0];
    d++;
    s++;
    n--;
  }
  if (n > 2 && s[1] == 'x' && s[0] == '#') {
    base = 16;
    s += 2;
  }
  if (n > 2 && s[1] == 'o' && s[0] == '#') {
    base = 8;
    s += 2;
  }
  if (n > 2 && s[1] == 'b' && s[0] == '#') {
    base = 2;
    s += 2;
  }
  for (; n--; s++) {
    ch = *s;
    if (ch != '_') {
      *d = ch;
      d++;
    } 
  }
  *d = 0x0;
  return base;
}

Id pz_numberize(void *b, Id token) {
  PZ_ACQUIRE_STR_D(dt, token, pzNil);
  char *ep;
  char n[1024];
  int base = pz_process_number((char *)&n, dt.s);
  long l = strtol((char *)&n, &ep, base);
  if (ep && *ep == '\0') return pz_long((int)l);
  double d = strtod(dt.s, &ep);
  if (ep && *ep == '\0') return pz_float(d);
  return pzNil;
}

Id pz_charize(void *b, Id token) {
  PZ_ACQUIRE_STR_D(dt, token, pzNil);
  const char *s = dt.s;
  int l = dt.l;
  // #\?
  if (l > 2 && s[0] == '#' && s[1] == '\\') {
    // #\?
    if (l == 3) return pz_char(s[2]);
    // ^#\space$
    if (l == 7) return pz_char(' ');
    // ^#\newline$
    if (l == 9) return pz_char('\n');
    // ^#\return$
    if (l == 8) return pz_char('\r');
    // ^#\xFF$
    if (l == 5 && s[2] == 'x') return pz_char(pz_hex_to_char(s+3));
  }
  return pzNil;
}

Id pz_atom(void *b, Id token) {
  Id r = pz_numberize(b, token); if (r) return r; 
  r = pz_charize(b, token); if (r) return r;
  return pz_intern(pz_to_symbol(token));
}

#define RETURN(v) { rv = v; goto finish; }
Id __pz_read_from(void *b, pz_interp_t *pi, Id tokens) {
  Id rv = pzNil;
  int quote = 0;

  pz_reset_errors();
  if (!tokens) return pzNil;
  Id token = pzNil;
  int ignore_token = 0;
next_token:
  if (pz_ary_len(b, tokens) == 0) 
      RETURN(pz_handle_parse_error_with_err_string_nh(
          "unexpected EOF while reading", pi->ps->line_number));
  do {
   if (pz_ary_len(b, tokens) == 0) RETURN(pzNil);
   pz_release(token);
   token = pz_retain0(pz_ary_shift(b, tokens));
   ignore_token = pz_string_equals_cp_i(token, "");
   if (!ignore_token && pz_string_equals_cp_i(token, "\n")) {
     pi->ps->line_number++;
     ignore_token = 1;
   }
  } while (ignore_token);
  if (pz_string_starts_with_cp_i(b, token, "'")) {
    Id word = pz_retain0(pz_string_sub_str_new(b, token, 1, -1));
    quote = 1;
    if (pz_string_len(b, word) > 0) {
      pz_release(token);
      token = word; 
    } else {
      pz_release(word);
      goto next_token;
    }
  }
  if (pz_string_equals_cp_i(token, "(")) {
    Id l = pz_ary_new(b);
    pz_ary_set_line_number(b, l, pi->ps->line_number);
    while (!pz_string_equals_cp_i(ca_f(tokens), ")")) {
       if (pz_string_equals_cp_i(ca_f(tokens), "\n")) {
         pi->ps->line_number++;
         pz_release_ja(pz_ary_shift(b, tokens));
       } else pz_ary_push(b, l, __pz_read_from(b, pi, tokens)); 
       CE(break) 
    }
    pz_release_ja(pz_ary_shift(b, tokens));
    RETURN(l);
  } else if (pz_string_equals_cp_i(token, ")")) {
    RETURN(pz_handle_parse_error_with_err_string_nh("unexpected )",
        pi->ps->line_number));
  } else { RETURN(pz_atom(b, token)); }

finish:
  pz_release(token);
  if (quote) {
    Id ql = pz_ary_new(b);
    pz_ary_push(b, ql, pz_intern(ISS("quote")));
    pz_ary_push(b, ql, rv);
    rv = ql;
  }
  return rv;
}

Id pz_read_from(void *b, pz_interp_t *pi, Id tokens) {
  pz_retain0(tokens);
  Id r = __pz_read_from(b, pi, tokens);
  pz_release(tokens);
  return r;
}

Id pz_parse(void *b, pz_interp_t *pi, Id va_s) { 
  pz_retain0(va_s);
  Id r =  pz_read_from(b, pi, pz_tokenize(b, pz_string_parse(b, va_s))); 
  pz_release(va_s);
  return r;
}

Id pz_eval(void *b, Id x, pz_interp_t* pi);

size_t rc_count = 0;
Id pz_begin(void *b, Id x, int start, pz_interp_t *pi);

Id pz_lambda(void *b, Id x, Id env) {
  Id l = pz_ary_new(b); 
  pz_ary_set_lambda(b, l);
  pz_ary_push(b, l, ca_s(x)); 
  Id c = pz_ary_new(b);
  int i = 2;
  pz_ary_push(b, c, pz_intern(pz_to_symbol(ISS("begin"))));
  Id v;
  while (pz_ary_iterate(b, x, &i, &v)) pz_ary_push(b, c, v);
  pz_ary_push(b, l, c); pz_ary_push(b, l, env);
  return l;
}

Id  __try_convert_to_floats(void *b, Id x) {
  Id a = pz_ary_new(b), n;
  int i = 0; 
  while (pz_ary_iterate(b, x, &i, &n)) {
    if (!pz_is_number(n)) return pzNil;
    pz_ary_push(b, a, PZ_TYPE(n) == PZ_TYPE_LONG ? pz_float(PZ_LONG(n)) : n);
  }
  return a;
}

Id  __try_convert_to_ints(void *b, Id x) {
  Id a = pz_ary_new(b), n0, n;
  int i = 0; 
  while (pz_ary_iterate(b, x, &i, &n0)) {
    n = cn(n0);
    if (!pz_is_number(n)) return pzNil;
    pz_ary_push(b, a, n);
  }
  return a;
}

#define ON_I \
  RG(tryg); \
  int t = (pz_ary_contains_only_type_i(b, x, PZ_TYPE_LONG) ? 1 : \
      (pz_ary_contains_only_type_i(b, x, PZ_TYPE_FLOAT) ? 2 : 0)); \
  if (t == 0) { \
      Id _try = __try_convert_to_ints(b, x);  \
      if (_try) { t = 1; x = tryg = _try; }} \
  if (t == 0) { \
      Id _try = __try_convert_to_floats(b, x);  \
      if (_try) { t = 2; x = tryg = _try; }} \
  int ai = PZ_LONG(ca_f(x)); int bi = PZ_LONG(ca_s(x)); \
  float af = PZ_FLOAT(ca_f(x)); float bf = PZ_FLOAT(ca_s(x)); \
  Id r = pzNil; \
  ai = ai; bi = bi; bf = bf; af = af;\
  if (t == 1) { 
#define ON_F ; } else if (t == 2) {
#define R  ; } return r;


Id pz_cmd_add(VB) { ON_I r = pz_long(ai + bi) ON_F r = pz_float(af + bf) R }
Id pz_cmd_sub(VB) { ON_I r = pz_long(ai - bi) ON_F r = pz_float(af - bf) R }
Id pz_cmd_mul(VB) { ON_I r = pz_long(ai * bi) ON_F r = pz_float(af * bf) R }
Id pz_cmd_div(VB) { ON_I r = pz_long(ai / bi) ON_F r = pz_float(af / bf) R }
Id pz_cmd_gt(VB) { ON_I r = cb(ai > bi) ON_F r = cb(af > bf) R }
Id pz_cmd_lt(VB) { ON_I r = cb(ai < bi) ON_F r = cb(af < bf) R }
Id pz_cmd_ge(VB) { ON_I r = cb(ai >= bi) ON_F r = cb(af >= bf) R }
Id pz_cmd_le(VB) { ON_I r = cb(ai <= bi) ON_F r = cb(af <= bf) R }
Id pz_cmd_eq_p(VB) { return cb(pz_eq_i(ca_f(x), ca_s(x))); }
Id pz_cmd_equal_p(VB) { return cb(pz_equals_i(ca_f(x), ca_s(x))); }
Id pz_cmd_length(VB) { return pz_long(pz_ary_len(b, x)); }
Id pz_cmd_cons(VB) { Id a = ca_f(x); Id r = pz_ary_new(b); 
    pz_ary_push(b, r, ca_f(a)); pz_ary_push(b, r, ca_s(a)); 
    return r; }
Id pz_cmd_car(VB) { return ca_f(ca_f(x)); }
Id pz_cmd_cdr(VB) { 
  Id a = pz_ary_clone_part(b, ca_f(x), 1, -1); 
  if (pz_ary_len(b, a) == 1) {
    Id r = pz_ary_shift(b, a);
    pz_release_ja(a);
    return r;
  }
  return a;
}
Id pz_cmd_list(VB)  { return pz_ary_clone(b, x); }
Id pz_cmd_display(VB) { 
  RG(sg);
  printf("%s", pz_string_ptr(sg = pz_ary_join_by_s(b, 
    pz_ary_map(b, x, pz_to_string), IS(" ")))); 
  fflush(stdout); 
  return pzNil;
}
Id pz_cmd_current_ms(VB) { return pz_long((int)pz_current_time_ms());}
Id pz_cmd_make_hash(VB) { return pz_ht_new(b); }
Id pz_cmd_hash_set_bang(VB) { return pz_ht_set(b, ca_f(x), ca_s(x), ca_th(x)); }
Id pz_cmd_hash_get(VB)  { return pz_ht_get(b, ca_f(x), ca_s(x)); }
Id pz_cmd_hash_delete_bang(VB) { return pz_ht_delete(b, ca_f(x), ca_s(x)); }
Id pz_cmd_make_vector(VB) { return pz_ary_new(b); }
Id pz_cmd_vector_set_bang(VB) { return pz_ary_set(b, ca_f(x), PZ_LONG(ca_s(x)), 
    ca_th(x)); }
Id pz_cmd_vector_get(VB) { return pz_ary_index(b, ca_f(x), PZ_LONG(ca_s(x))); }
Id pz_cmd_vector_push(VB) { return pz_ary_push(b, ca_f(x), ca_s(x)); }
Id pz_cmd_vector_pop_bang(VB)  { return pz_ary_pop(b, ca_f(x)); }
Id pz_cmd_vector_shift_bang(VB) { return pz_ary_shift(b, ca_f(x)); }
Id pz_cmd_vector_length(VB) { return pz_long(pz_ary_len(b, ca_f(x))); }
Id pz_cmd_string_constant(VB) { 
    return pz_ary_index(b, pz_string_constants, PZ_LONG(ca_f(x))); }
Id pz_cmd_string_split(VB) { 
    return pz_string_split2(b, ca_f(x), ca_s(x)); }

Id pz_cmd_vector_each(VB) { return __pz_vector_find(b, x, pi, sf, 0); }
Id pz_cmd_vector_find(VB) { return __pz_vector_find(b, x, pi, sf); }

Id pz_cmd_hash_each(VB) { 
  RG(sg);
  Id e = sg = pz_env_new(b, sf->env);
  Id lambda = ca_s(x);
  Id vdecl = ca_f(lambda);
  int l = pz_ary_len(b, vdecl);
  Id pk = l > 0 ? ca_f(vdecl) : pzNil;
  Id pv = l > 1 ? ca_s(vdecl) : pzNil;

  pz_ht_iterate_t h;
  h.initialized = 0;
  pz_ht_entry_t *hr;
  if (!pz_e_stack_frame(b, x, pi, sf->env)) return pzNil;
  pz_stack_frame_t *_sf = PZ_CURRENT_STACK_FRAME;
  _sf->x = x;
  _sf->env = e;

  while ((hr = pz_ht_iterate(b, ca_f(x), &h))) {
    if (pk) pz_ht_set(b, e, pk, hr->va_key);
    if (pv) pz_ht_set(b, e, pv, hr->va_value);
    pz_dispatch(b, lambda_body(lambda), pi, _sf);
  }

  pi->nested_depth--;
  return pzNil;
}

Id pz_cmd_rx_match_string(VB) { 
  return cb(pz_rx_match(b, ca_f(x), ca_s(x)));
}

Id pz_cmd_rand(VB) {
  Id n = ca_f(x);
  if (!n) n = pz_long(1 << 16);
  return pz_long(rand() % PZ_LONG(n));
}

Id pz_cmd_shl(VB) { return pz_long(PZ_LONG(ca_f(x)) << PZ_LONG(ca_s(x))); }
Id pz_cmd_shr(VB) { return pz_long(PZ_LONG(ca_f(x)) >> PZ_LONG(ca_s(x))); }
Id pz_cmd_b_or(VB) { return pz_long(PZ_LONG(ca_f(x)) | PZ_LONG(ca_s(x))); }
Id pz_cmd_b_and(VB) { return pz_long(PZ_LONG(ca_f(x)) & PZ_LONG(ca_s(x))); }
Id pz_cmd_b_xor(VB) { return pz_long(PZ_LONG(ca_f(x)) ^ PZ_LONG(ca_s(x))); }

Id pz_cmd_not(VB) { return cb(cnil(ca_f(x))); }

Id pz_cmd_sleep(VB) { 
    ON_I usleep((size_t)ai * 1000000)
    ON_F usleep((size_t)(af * 1000000.0)) R }

Id pz_cmd_type_of(VB) { 
  Id v = ca_f(x);
  int t = PZ_TYPE(v);
  const char *rs = (t == PZ_TYPE_ARRAY && pz_ary_is_lambda(b, v)) ?
      "lambda" : pz_type_to_cp(t);
  
  return ISS(rs);
}
Id pz_cmd_string_to_number(VB) { return pz_numberize(b, ca_f(x)); }
Id pz_cmd_number_to_string(VB) { 
    char buf[1024];
    snprintf(buf, 1023, "#x%lx", PZ_LONG(ca_f(x)));
    return S(buf); }
Id pz_load(void *b, Id _fn, pz_interp_t *pi = 0);
Id pz_cmd_load(VB)  { return pz_load(b, ca_f(x), pi); }
Id pz_cmd_eval(VB)  { 
  if (!pz_e_stack_frame(b, x, pi, sf->env)) return pzNil;
  pz_stack_frame_t *_sf = PZ_CURRENT_STACK_FRAME;
  _sf->x = x;
  _sf->func_name = ISS("eval");
  _sf->last = 1;
  Id r = pz_dispatch(b, ca_f(x), pi, _sf); 
  pi->nested_depth--;
  return r;
}
Id pz_cmd_string_to_symbol(VB) { return pz_to_symbol(ca_f(x)); }
Id pz_cmd_symbol_to_string(VB) { return pz_to_string(ca_f(x)); }
Id pz_cmd_make_string(VB) { return S(""); }
Id pz_cmd_string_length(VB) { return pz_long(pz_string_len(b, ca_f(x))); }
Id pz_cmd_string_ref(VB) { return pz_string_char_at(b, ca_f(x), PZ_LONG(ca_s(x))); }
Id pz_cmd_string_append(VB) { 
    return pz_ary_join_by_s(b, pz_ary_map(b, x, pz_to_string), IS("")); }
Id pz_cmd_string_append_bang(VB) { 
    return pz_string_append(b, ca_f(x), ca_s(x)); }
Id pz_cmd_string_copy(VB) { 
    return pz_string_sub_str_new(b, ca_f(x), 0, -1); }
Id pz_cmd_substring(VB) { 
    return pz_string_sub_str_new(b, ca_f(x), PZ_LONG(ca_s(x)), PZ_LONG(ca_th(x))); }
Id pz_cmd_inspect(VB) { 
    printf("%s ", pz_string_ptr(ca_f(x)));
    pz_print_dump(b, ca_s(x), PZ_DUMP_INSPECT | PZ_DUMP_RECURSE); 
    printf("\n");
    return pz_retain0(ca_s(x)); }
Id pz_cmd_vector_tail(VB) { return pz_ary_clone_part(b, ca_f(x), PZ_LONG(ca_s(x)), -1); }
Id pz_cmd_dump(VB) { 
    printf("%s ", pz_string_ptr(ca_f(x)));
    pz_print_dump(b, ca_s(x), PZ_DUMP_DEBUG | PZ_DUMP_RECURSE); 
    printf("\n");
    return pz_retain0(ca_s(x)); }
Id pz_cmd_vector_append(VB) { return pz_ary_new_join(b, ca_f(x), ca_s(x)); }

Id pz_cmd_hash_code(VB) { return pz_long(pz_hash_var(b, ca_f(x))); }
Id pz_cmd_cfunc_to_bin_adr_s(VB) { return pz_cfunc_to_bin_adr_s(b, ca_f(x)); }
Id pz_cmd_va_to_bin_adr_s(VB) { return pz_va_to_bin_adr_s(b, ca_f(x)); }

const char *pz_std_n[] = {"+", "-", "*", "/", ">", "<", ">=", "<=", "=",
    "equal?", "eq?", "length", "cons", "car", "cdr", "list",
    "display", "current-ms", "make-hash", "hash-set!", "hash-get",
    "hash-delete!", "make-vector", "vector-get", "vector-set!",
    "vector-push!", "vector-pop!", "vector-shift!", "vector-length",
    "vector-tail", "string-constant", "string-split", "vector-each",
    "vector-find", "hash-each", "rx-match-string", "rand", "<<", ">>",
    "not", "sleep", "|", "&", "^", "type-of", "string->number",
    "number->string", "load", "eval", "string->symbol", "symbol->string",
    "string-append", "string-append!", "string-copy", "substring", "make-string",
    "string-length", "string-ref", "inspect", "dump", "vector-append",
    "hash-code", "cfunc->binary-addr-s", "va->binary-addr-s", 0};

Id (*pz_std_f[])(VB) = {pz_cmd_add, pz_cmd_sub, pz_cmd_mul, pz_cmd_div,
    pz_cmd_gt, pz_cmd_lt, pz_cmd_ge, pz_cmd_le, pz_cmd_eq_p,
    pz_cmd_equal_p, pz_cmd_eq_p, pz_cmd_length, pz_cmd_cons, pz_cmd_car,
    pz_cmd_cdr, pz_cmd_list, pz_cmd_display, pz_cmd_current_ms,
    pz_cmd_make_hash, pz_cmd_hash_set_bang, pz_cmd_hash_get,
    pz_cmd_hash_delete_bang, pz_cmd_make_vector, pz_cmd_vector_get,
    pz_cmd_vector_set_bang, pz_cmd_vector_push, pz_cmd_vector_pop_bang,
    pz_cmd_vector_shift_bang, pz_cmd_vector_length, pz_cmd_vector_tail,
    pz_cmd_string_constant, pz_cmd_string_split, pz_cmd_vector_each,
    pz_cmd_vector_find, pz_cmd_hash_each, pz_cmd_rx_match_string,
    pz_cmd_rand, pz_cmd_shl, pz_cmd_shr, pz_cmd_not, pz_cmd_sleep,
    pz_cmd_b_or, pz_cmd_b_and, pz_cmd_b_xor, pz_cmd_type_of,
    pz_cmd_string_to_number, pz_cmd_number_to_string, pz_cmd_load,
    pz_cmd_eval, pz_cmd_string_to_symbol, pz_cmd_symbol_to_string,
    pz_cmd_string_append, pz_cmd_string_append_bang,
    pz_cmd_string_copy, pz_cmd_substring, pz_cmd_make_string,
    pz_cmd_string_length, pz_cmd_string_ref, pz_cmd_inspect, pz_cmd_dump,
    pz_cmd_vector_append, pz_cmd_hash_code,
    pz_cmd_cfunc_to_bin_adr_s, pz_cmd_va_to_bin_adr_s, 0};


void pz_add_std_functions(void *b, Id env) {
  int i = 0;
  while (pz_std_n[i] != 0) { pz_define_func(b, pz_std_n[i], pz_std_f[i],
      env); i++; }
}

void pz_add_globals(void *b, Id env) {
  pz_add_std_functions(b, env);
}

Id pz_to_string(void *b, Id exp) {
  char dsc[16834];
  size_t l = 0;
  pz_dump_to_string(b, exp, (char *)&dsc, &l, PZ_DUMP_RECURSE);
  return pz_string_new(b, dsc, l);
}

Id pz_to_inspect_string(void *b, Id exp) {
  char dsc[16834];
  size_t l = 0;
  pz_dump_to_string(b, exp, (char *)&dsc, &l, PZ_DUMP_RECURSE | PZ_DUMP_INSPECT);
  return pz_string_new(b, dsc, l);
}

void pz_repl(void *b, FILE *f, Id filename, int interactive) {
  pz_retain0(filename);
  pz_parse_t ps;
  ps.filename = filename;
  ps.interactive = interactive;
  pz_interp_t pi;
  memset(&pi, 0, sizeof(pi));
  pi.ps = &ps;
  while (1) {
    ps.line_number = 1;
    pi.stack_overflow = 0;
    pi.nested_depth = 0;
    Id parsed = pz_retain(filename, pz_parse(b, &pi,
        pz_input(b, &pi, f, pz_perf_mode ? "perf>" : "ponzi> ")));
    Id val = pz_retain0(pz_e_exec_procedure(b, parsed, &pi));
    pz_release(parsed);
    if (feof(f)) break;
    if (interactive) {
      RG(sg);
      printf("===> %s\n", pz_string_ptr(sg = pz_to_inspect_string(b, val)));
    }
    pz_release(val);
    pz_mem_dump(b);
  }
  pz_release(filename);
}


Id pz_load(void *b, Id _fn, pz_interp_t *pi)  {
  const char *fn = pz_string_ptr(_fn);
  FILE *f;
  int interactive = pi ? pi->ps->interactive : 0;
  f = fopen(fn, "r");
  if (!f) {
    if (interactive) pz_handle_error(!f, "fopen", fn) ;
    return pzNil;
  }
  pz_repl(b, f, _fn, 0);
  return pzTrue;
}

