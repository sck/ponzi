/*
 * Scheme parsing code, port of Norvig's lis.py:
 * <http://norvig.com/lispy.html>
 */

Id string_ref;

Id pz_to_string(void *b, Id exp);
#define VB void *b, Id env

Id pz_string_parse(void *b, Id s) {
  if (!s.s) return pzNil;
  Id ary = pz_retain0(pz_string_split(b, s, '"'));
  if (!ary.s) return pzNil;
  int string_mode = 0;
  Id v;
  int i = 0;
  Id r = pz_retain0(pz_ary_new(b));
  while ((v = pz_ary_iterate(b, ary, &i)).s) {
    if (!string_mode) {
      pz_ary_push(b, r, v);
    } else {
      int i = pz_register_string_ref(b, v);
      Id sr = IS("(string-ref ");
      pz_string_append(b, sr, pz_string_new_number(b, pz_int(i)));
      pz_string_append(b, sr, IS(")"));
      pz_ary_push(b, r, sr);
    }
    string_mode = 1 - string_mode;
  }
  pz_release(ary);
  Id rr = pz_ary_join_by_s(b, r, IS(""));
  pz_release(r);
  return rr;
}

Id pz_tokenize(void *b, Id va_s) {
  if (!va_s.s) return pzNil;
  pz_retain0(va_s);
  Id r1, r2;
  Id r = pz_string_split(b,
      (r1 = pz_string_replace(b, 
        (r2 = pz_string_replace(b, va_s, IS("("), IS(" ( "))), 
      IS(")"), IS(" ) "))), ' ');
  pz_release_ja(r1); pz_release_ja(r2); pz_release(va_s);
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
  if (ep && *ep == '\0') return pz_int((int)l);
  float f = strtof(dt.s, &ep);
  if (ep && *ep == '\0') return pz_float(f);
  return pzNil;
}

Id pz_atom(void *b, Id token) {
  Id r = pz_numberize(b, token);
  if (r.s) return r; 
  return pz_intern(pz_to_symbol(token));
}

#define RETURN(v) { rv = v; goto finish; }
Id __pz_read_from(void *b, Id tokens) {
  Id rv = pzNil;
  int quote = 0;

  pz_reset_errors(b);
  if (!tokens.s) return pzNil;
  Id token = pzNil;
next_token:
  if (pz_ary_len(b, tokens) == 0) 
      return pz_handle_error_with_err_string_nh(__FUNCTION__, 
          "unexpected EOF while reading");
  do {
   pz_release(token);
   token = pz_retain0(pz_ary_unshift(b, tokens));
  } while (pz_string_equals_cp_i(token, ""));
  if (pz_string_starts_with_cp_i(b, token, "'")) {
    Id word = pz_retain0(pz_string_sub_str_new(b, token, 1, -1));
    quote = 1;
    if (pz_string_len(b, word) > 0) {
      token = word; 
    } else {
      pz_release(token);
      goto next_token;
    }
  }
  if (pz_string_equals_cp_i(token, "(")) {
    Id l = pz_ary_new(b);
    while (!pz_string_equals_cp_i(ca_f(tokens), ")")) {
        pz_ary_push(b, l, __pz_read_from(b, tokens)); CE(break) }
    pz_ary_unshift(b, tokens);
    RETURN(l);
  } else if (pz_string_equals_cp_i(token, ")")) {
    return pz_handle_error_with_err_string_nh(__FUNCTION__, 
        "unexpected )");
  } else RETURN(pz_atom(b, token));

finish:
  pz_release(token);
  if (quote) {
    Id ql = pz_ary_new(b);
    pz_ary_push(b, ql, pz_intern(IS("quote")));
    pz_ary_push(b, ql, rv);
    rv = ql;
  }
  return rv;
}

Id pz_read_from(void *b, Id tokens) {
  pz_retain0(tokens);
  Id r = __pz_read_from(b, tokens);
  pz_release(tokens);
  return r;
}

Id pz_parse(void *b, Id va_s) { 
  pz_retain0(va_s);
  Id r =  pz_read_from(b, pz_tokenize(b, pz_string_parse(b, va_s))); 
  pz_release(va_s);
  return r;
}

#define DC2B(va) pz_deep_copy(b, pz_perf, va)
#define DC2P(va) pz_deep_copy(pz_perf, b, va)
#define pz_eval2(x, e, l) pz_eval(b, x, e, this, this, l)
size_t nested_depth = 0;
size_t stack_overflow = 0;
size_t rc_count = 0;
Id pz_begin(void *b, Id x, int start, Id _env, Id this, Id previous);
Id pz_eval(void *b, Id x, Id _env, Id this, Id previous, int last) {
  Id x0, exp, val, var, vars, rv, env;
  nested_depth++;
  if (stack_overflow) return pzNil;
  if (nested_depth > 2000) {
    printf("STACKoverflow\n");
    stack_overflow = 1;
  }
  //D("x", x);
  pz_retain0(_env);
  pz_garbage_collect(b);
  Id func_name = pzNil;
tail_rc_start:
  val= pzNil; vars = pzNil; rv = pzNil;
  if (!x.s) RETURN(pzNil);
  //printf("START: %x %lx\n", PZ_ADR(vars), &vars);
  env = (_env.s ? _env : pz_globals);
  if (PZ_TYPE(x) == PZ_TYPE_SYMBOL) {
    if (pz_string_equals_cp_i(x, "globals")) RETURN(pz_globals);
    if (pz_string_equals_cp_i(x, "string-interns")) RETURN(pz_string_interns);
    if (pz_string_equals_cp_i(x, "symbol-interns")) RETURN(pz_symbol_interns);
    if (pz_string_equals_cp_i(x, "string-refs")) RETURN(pz_string_refs);
    if (pz_string_equals_cp_i(x, "string-refs-dict")) RETURN(pz_string_refs_dict);
    if (pz_string_equals_cp_i(x, "#t")) RETURN(pzTrue);
    if (pz_string_equals_cp_i(x, "#f")) RETURN(pzNil);
    RETURN(pz_env_find(b, env, x));
  } else if (PZ_TYPE(x) != PZ_TYPE_ARRAY) {
    RETURN(x); // constant literal
  } 
  if (PZ_TYPE(x) == PZ_TYPE_ARRAY && pz_ary_len(b, x) == 3) {
    Id m = ca_s(x);
    if (PZ_TYPE(m) == PZ_TYPE_SYMBOL && pz_string_equals_cp_i(m, ".")) {
      Id a = pz_retain0(pz_ary_new(b));
      pz_ary_push(b, a, pz_eval2(ca_f(x), env, 0));
      pz_ary_push(b, a, pz_eval2(ca_th(x), env, 1));
      pz_release(a);
      RETURN(a);
    }
  }
  if (pz_ary_len(b, x) == 0) {
    RETURN(pz_handle_error_with_err_string(__FUNCTION__, "No proc given", 
        pz_string_ptr(pz_to_string(b, func_name)))); 
  }
  x0 = ca_f(x);
  if (!pz_is_string(x0)) {
    RETURN(pz_handle_error_with_err_string(__FUNCTION__, "Not a symbol type", 
        pz_string_ptr(pz_to_string(b, func_name)))); 
  }
  if (pz_string_equals_cp_i(x0, "quote")) {
    RETURN(ca_s(x));
  } else if (pz_string_equals_cp_i(x0, "/#")) { // (/# ^regexp$)
    Id rx = pz_rx_new(pz_ary_join_by_s(b,  
        pz_ary_clone_part(b, x, 1, -1), IS(" ")));
    return rx;
  } else if (pz_string_equals_cp_i(x0, "if")) { // (if test conseq alt)
    Id test = ca_s(x), conseq = ca_th(x), alt = ca_fth(x);
    Id t = pz_eval2(test, env, 0);
    RETURN(cnil2(b, t).s ? pz_eval2(conseq, env, 1) : pz_eval2(alt, env, 1));
  } else if (pz_string_equals_cp_i(x0, "set!")) { // (set! var exp)
    var = ca_s(x), exp = ca_th(x);
    pz_env_find_and_set(b, env, var, pz_eval2(exp, env, 0));
  } else if (pz_string_equals_cp_i(x0, "define")) { // (define var exp)
    var = ca_s(x), exp = ca_th(x);
    RETURN(pz_ht_set(b, env, var, pz_eval2(exp, env, 1)));
  } else if (pz_string_equals_cp_i(x0, "lambda")) { //(lambda (var*) exp)
    Id l = pz_ary_new(b); pz_ary_set_lambda(b, l);
    pz_ary_push(b, l, ca_s(x)); 
    Id c = pz_ary_new(b);
    int i = 2;
    pz_ary_push(b, c, pz_intern(pz_to_symbol(IS("begin"))));
    Id v;
    while ((v = pz_ary_iterate(b, x, &i)).s) pz_ary_push(b, c, v);
    pz_ary_push(b, l, c); pz_ary_push(b, l, env);
    RETURN(l);
  } else if (pz_string_equals_cp_i(x0, "begin")) {  // (begin exp*)
    RETURN(pz_begin(b, x, 1, env, this, this));
  } else if (pz_string_equals_cp_i(x0, "begin-perf")) {  // (begin-perf exp*)
    if (b == pz_perf) return pzNil;
    RETURN(DC2B(pz_begin(pz_perf, DC2P(x), 1, 
        env.s == pz_globals.s ? pzNil : DC2P(env), //DC2P(env), 
        DC2P(this), DC2P(this))));
  } else {  // (proc exp*)
    Id v;
    vars = pz_retain0(pz_ary_new(b));
    int i = 1;
    while ((v = pz_ary_iterate(b, x, &i)).s) 
        pz_ary_push(b, vars, pz_eval2(v, env, 0));
    func_name = x0;
    Id lambda = pz_env_find(b, env, func_name);
    if (!lambda.s) { 
      D("x", x);
      D("func_name", func_name);
      RETURN(pz_handle_error_with_err_string(__FUNCTION__, "Unknown proc", 
          pz_string_ptr(pz_to_string(b, func_name)))); 
    }
    if (pz_is_type_i(lambda, PZ_TYPE_CFUNC)) {
      RETURN(pz_call(b, lambda, env, vars));
    }
    int tail_rc = 0;
    if (pz_equals_i(func_name, this)) tail_rc = last;
    Id e = tail_rc ? env : pz_env_new(b, pz_ary_index(b, lambda, 2)), p;
    Id vdecl = pz_ary_index(b, lambda, 0);
    if (PZ_TYPE(vdecl) == PZ_TYPE_ARRAY) {
      if (pz_ary_len(b, vdecl) != pz_ary_len(b, vars))  {
         char es[1024]; 
         snprintf(es, 1023, "Parameter count mismatch! (have %d, expected %d)", 
             pz_ary_len(b, vars), pz_ary_len(b, vdecl));  
         RETURN(pz_handle_error_with_err_string(__FUNCTION__, 
             es, pz_string_ptr(func_name)));
      }
      i = 0;
      while ((p = pz_ary_iterate(b, vdecl, &i)).s) 
          pz_ht_set(b, e, p, pz_ary_index(b, vars, i - 1));
    } else {
      pz_ht_set(b, e, vdecl, vars);
    }
    if (tail_rc) RETURN(pzTail);
    Id r =  pz_eval(b, pz_ary_index(b, lambda, 1), e, func_name, this, 0);
    RETURN(r);
  }

finish:
  pz_release(vars);
  if (rv.s == pzTail.s && !pz_equals_i(this, previous)) { goto tail_rc_start; }
  pz_release(_env);
  nested_depth--;
  return rv;
}

Id pz_begin(void *b, Id x, int start, Id env, Id this, Id previous) {
  Id val = pzNil, exp;
  int i = start;
  int l = pz_ary_len(b, x);
  pz_retain(this, this);
  pz_retain(this, previous);
  pz_retain(x, env);
  pz_retain(this, x);
  while ((exp = pz_ary_iterate(b, x, &i)).s) 
    val = pz_eval(b, exp, env, this, previous, l == i);
  pz_release(this);
  pz_release(previous);
  pz_release(x);
  pz_release(env);
  return val;
}

Id  __try_convert_to_floats(void *b, Id x) {
  Id a = pz_ary_new(b), n;
  int i = 0; 
  while ((n = pz_ary_iterate(b, x, &i)).s) {
    if (!pz_is_number(n)) return pzNil;
    pz_ary_push(b, a, PZ_TYPE(n) == PZ_TYPE_INT ? pz_float(PZ_INT(n)) : n);
  }
  return a;
}

Id  __try_convert_to_ints(void *b, Id x) {
  Id a = pz_ary_new(b), n0, n;
  int i = 0; 
  while ((n0 = pz_ary_iterate(b, x, &i)).s) {
    n = cn(n0);
    if (!pz_is_number(n)) return pzNil;
    pz_ary_push(b, a, n);
  }
  return a;
}

#define ON_I \
  int t = (pz_ary_contains_only_type_i(b, x, PZ_TYPE_INT) ? 1 : \
      (pz_ary_contains_only_type_i(b, x, PZ_TYPE_FLOAT) ? 2 : 0)); \
  if (t == 0) { \
      Id try = __try_convert_to_ints(b, x);  \
      if (try.s) { t = 1; x = try; }} \
  if (t == 0) { \
      Id try = __try_convert_to_floats(b, x);  \
      if (try.s) { t = 2; x = try; }} \
  int ai = PZ_INT(ca_f(x)); int bi = PZ_INT(ca_s(x)); \
  float af = PZ_FLOAT(ca_f(x)); float bf = PZ_FLOAT(ca_s(x)); \
  Id r = pzNil; \
  if (t == 1) { 
#define ON_F ; } else if (t == 2) {
#define R  ; } return r;


Id pz_add(VB, Id x) { ON_I r = pz_int(ai + bi) ON_F r = pz_float(af + bf) R }
Id pz_sub(VB, Id x) { ON_I r = pz_int(ai - bi) ON_F r = pz_float(af - bf) R }
Id pz_mul(VB, Id x) { ON_I r = pz_int(ai * bi) ON_F r = pz_float(af * bf) R }
Id pz_div(VB, Id x) { ON_I r = pz_int(ai / bi) ON_F r = pz_float(af / bf) R }
Id pz_gt(VB, Id x) { ON_I r = cb(ai > bi) ON_F r = cb(af > bf) R }
Id pz_lt(VB, Id x) { ON_I r = cb(ai < bi) ON_F r = cb(af < bf) R }
Id pz_ge(VB, Id x) { ON_I r = cb(ai >= bi) ON_F r = cb(af >= bf) R }
Id pz_le(VB, Id x) { ON_I r = cb(ai <= bi) ON_F r = cb(af <= bf) R }
Id pz_eq(VB, Id x) { return cb(pz_equals_i(ca_f(x), ca_s(x))); }
Id pz_length(VB, Id x) { return pz_int(pz_ary_len(b, x)); }
Id pz_cons(VB, Id x) { Id a = ca_f(x); Id r = pz_ary_new(b); 
    pz_ary_push(b, r, ca_f(a)); pz_ary_push(b, r, ca_s(a)); 
    return r; }
Id pz_car(VB, Id x) { return ca_f(ca_f(x)); }
Id pz_cdr(VB, Id x) { Id a = ca_f(x); return pz_ary_index(b, a, -1); }
Id pz_list(VB, Id x) { return x; }
Id pz_list_p(VB, Id x) { return cb(pz_is_type_i(x, PZ_TYPE_ARRAY)); }
Id pz_null_p(VB, Id x) { return cb(cnil(x)); }
Id pz_symbol_p(VB, Id x) { return cb(pz_is_type_i(x, PZ_TYPE_SYMBOL)); }
Id pz_display(VB, Id x) { 
  printf("%s", pz_string_ptr(pz_ary_join_by_s(b, 
    pz_ary_map(b, x, pz_to_string), IS(" ")))); 
  fflush(stdout); 
  return pzNil;
}
Id pz_newline(VB, Id x) { printf("\n"); return pzNil;}
Id pz_resetline(VB, Id x) { printf("\r"); fflush(stdout); return pzNil;}
Id pz_current_ms(VB, Id x) { return pz_int((int)pz_current_time_ms());}
Id pz_make_hash(VB, Id x) { return pz_ht_new(b); }
Id pz_hash_set(VB, Id x) { return pz_ht_set(b, ca_f(x), ca_s(x), ca_th(x)); }
Id pz_hash_get(VB, Id x) { return pz_ht_get(b, ca_f(x), ca_s(x)); }
Id pz_make_vector(VB, Id x) { return pz_ary_new(b); }
Id pz_vector_set(VB, Id x) { return pz_ary_set(b, ca_f(x), PZ_INT(ca_s(x)), 
    ca_th(x)); }
Id pz_vector_get(VB, Id x) { return pz_ary_index(b, ca_f(x), PZ_INT(ca_s(x))); }
Id pz_vector_push(VB, Id x) { return pz_ary_push(b, ca_f(x), ca_s(x)); }
Id pz_vector_pop(VB, Id x) { return pz_ary_pop(b, ca_f(x)); }
Id pz_vector_unshift(VB, Id x) { return pz_ary_unshift(b, ca_f(x)); }
Id pz_vector_len(VB, Id x) { return pz_int(pz_ary_len(b, ca_f(x))); }
Id pz_string_ref(VB, Id x) { 
    return pz_ary_index(b, pz_string_refs, PZ_INT(ca_f(x))); }
Id _pz_string_split(VB, Id x) { 
    return pz_string_split2(b, ca_f(x), ca_s(x)); }

Id pz_vector_each(VB, Id x) { 
  Id this = pzNil;
  Id e = pz_retain0(pz_env_new(b, env));
  Id lambda = ca_s(x);
  Id vdecl, pn;
  int l;
  if (!pz_is_type_i(lambda, PZ_TYPE_CFUNC)) {
    vdecl = ca_f(lambda);
    l = pz_ary_len(b, vdecl);
    pn = l > 0 ? ca_f(vdecl) : pzNil;
  }
  int i = 0; 
  Id v;
  while ((v = pz_ary_iterate(b, ca_f(x), &i)).s) {
    if (pz_is_type_i(lambda, PZ_TYPE_CFUNC)) {
      Id vars = pz_retain0(pz_ary_new(b));
      pz_ary_push(b, vars, v);
      pz_call(b, lambda, e, vars);
      pz_release(vars);
    } else {
      if (pn.s) pz_ht_set(b, e, pn, v);
      pz_eval(b, ca_s(lambda), e, pzNil, pzNil, 0);
    }
  }
  pz_release(e);
  return pzNil;
}

Id pz_hash_each(VB, Id x) { 
  Id this = pzNil;
  Id e = pz_env_new(b, env);
  Id lambda = ca_s(x);
  Id vdecl = ca_f(lambda);
  int l = pz_ary_len(b, vdecl);
  Id pk = l > 0 ? ca_f(vdecl) : pzNil;
  Id pv = l > 1 ? ca_s(vdecl) : pzNil;

  pz_ht_iterate_t h;
  h.initialized = 0;
  pz_ht_entry_t *hr;
  while ((hr = pz_ht_iterate(b, ca_f(x), &h))) {
    if (pk.s) pz_ht_set(b, e, pk, hr->va_key);
    if (pv.s) pz_ht_set(b, e, pv, hr->va_value);
    pz_eval(b, ca_s(lambda), e, pzNil, pzNil, 0);
  }
  return pzNil;
}
Id _pz_rx_match_string(VB, Id x) { 
  return cb(pz_rx_match(b, ca_f(x), ca_s(x)));
}

Id pz_rand(VB, Id x) {
  Id n = ca_f(x);
  if (!n.s) n = pz_int(1 << 16);
  return pz_int(rand() % PZ_INT(n));
}

Id pz_shl(VB, Id x) { return pz_int(PZ_INT(ca_f(x)) << PZ_INT(ca_s(x))); }
Id pz_shr(VB, Id x) { return pz_int(PZ_INT(ca_f(x)) >> PZ_INT(ca_s(x))); }
Id pz_b_or(VB, Id x) { return pz_int(PZ_INT(ca_f(x)) | PZ_INT(ca_s(x))); }
Id pz_b_and(VB, Id x) { return pz_int(PZ_INT(ca_f(x)) & PZ_INT(ca_s(x))); }
Id pz_b_xor(VB, Id x) { return pz_int(PZ_INT(ca_f(x)) ^ PZ_INT(ca_s(x))); }

Id pz_and(VB, Id x) { return cb(!cnil(ca_f(x)) && !cnil(ca_s(x))); }
Id pz_or(VB, Id x) { return cb(!cnil(ca_f(x)) || !cnil(ca_s(x))); }
Id pz_not(VB, Id x) { return cb(cnil(ca_f(x))); }

Id pz_sleep(VB, Id x) { 
    ON_I usleep((size_t)ai * 1000000)
    ON_F usleep((size_t)(af * 1000000.0)) R }

Id pz_type_of(VB, Id x) { return S(pz_type_to_cp(PZ_TYPE(ca_f(x)))); }
Id pz_string_to_number(VB, Id x) { return pz_numberize(b, ca_f(x)); }
Id pz_boolean_p(VB, Id x) { return cb(PZ_TYPE(ca_f(x)) == PZ_TYPE_BOOL); }

char *pz_std_n[] = {"+", "-", "*", "/", ">", "<", ">=", "<=", "=",
    "equal?", "eq?", "length", "cons", "car", "cdr", "list", "list?", 
    "null?", "symbol?", "display", "newline", "resetline", "current-ms",
    "make-hash", "hash-set!", "hash-get", "make-vector", "vector-get",
    "vector-set!", "vector-push!", "vector-pop!", "vector-unshift!",
    "vector-len", "string-ref", "string-split", "vector-each",
    "hash-each", "rx-match-string", "rand", "<<", ">>", "and", "or",
    "not", "sleep", "|", "&", "^", "type-of", "string->number",
    "boolean?", 0};

Id (*pz_std_f[])(void *b, Id, Id) = {pz_add, pz_sub, pz_mul, pz_div, 
    pz_gt, pz_lt, pz_ge, pz_le, pz_eq, pz_eq, pz_eq, pz_length, pz_cons,
    pz_car, pz_cdr, pz_list, pz_list_p, pz_null_p, pz_symbol_p,
    pz_display, pz_newline, pz_resetline, pz_current_ms, pz_make_hash,
    pz_hash_set, pz_hash_get, pz_make_vector, pz_vector_get,
    pz_vector_set, pz_vector_push, pz_vector_pop, pz_vector_unshift,
    pz_vector_len, pz_string_ref, _pz_string_split, pz_vector_each,
    pz_hash_each, _pz_rx_match_string, pz_rand, pz_shl, pz_shr, pz_and,
    pz_or, pz_not, pz_sleep, pz_b_or, pz_b_and, pz_b_xor, pz_type_of,
    pz_string_to_number, pz_boolean_p, 0};


void pz_add_std_functions(void *b, Id env) {
  int i = 0;
  while (pz_std_n[i] != 0) { pz_define_func(b, pz_std_n[i], pz_std_f[i], env); i++; }
}

void pz_add_perf_symbols(void *b) {
  //S_icounter = IS("icounter");
}

void pz_add_globals(void *b, Id env) {
  pz_add_std_functions(b, env);
}

Id pz_to_inspect(void *b, Id exp) {
  char dsc[16834];
  pz_dump_to_string(b, exp, (char *)&dsc, PZ_DUMP_RECURSE | PZ_DUMP_INSPECT);
  return pz_string_new_c(b, dsc);
}

Id pz_to_string(void *b, Id exp) {
  char dsc[16834];
  pz_dump_to_string(b, exp, (char *)&dsc, PZ_DUMP_RECURSE);
  return pz_string_new_c(b, dsc);
}

void pz_repl(void *b, FILE *f, Id filename, int interactive) {
  pz_retain0(filename);
  while (1) {
    stack_overflow = 0;
    nested_depth = 0;
    Id parsed = pz_retain(filename, pz_parse(b, 
        pz_input(b, f, interactive, pz_perf_mode ? "perf>" : "ponzi> ")));
    Id val = pz_eval(b, parsed, pz_globals, filename, pzNil, 1);
    pz_release(parsed);
    if (feof(f)) break;
    Id s;
    if (interactive) 
        printf("===> %s\n", pz_string_ptr(pz_to_string(b, val)));
    pz_garbage_collect_full(b);
    pz_garbage_collect_full(b);
    pz_garbage_collect_full(b);
    pz_mem_dump(b);
  }
  pz_release(filename);
}
