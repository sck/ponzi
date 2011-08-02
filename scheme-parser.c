/*
 * Scheme parsing code, port of Norvig's lis.py:
 * <http://norvig.com/lispy.html>
 */

#define IS(s) cl_intern(S(s))

Id string_ref;

Id cl_string_parse(void *b, Id s) {
  if (!s.s) return clNil;
  Id ary = cl_string_split(b, s, '"');
  if (!ary.s) return clNil;
  int string_mode = 0;
  Id v;
  int i = 0;
  Id r = cl_ary_new(b);
  while ((v = cl_ary_iterate(b, ary, &i)).s) {
    if (!string_mode) {
      cl_ary_push(b, r, v);
    } else {
      cl_ary_push(b, string_ref, v);
      Id sr = S("(string-ref ");
      cl_string_append(b, sr, cl_string_new_number(b, 
          cl_int(cl_ary_len(b, string_ref) - 1)));
      cl_string_append(b, sr, S(")"));
      cl_ary_push(b, r, sr);
    }
    string_mode = 1 - string_mode;
  }
  return cl_ary_join_by_s(b, r, S(""));
}

Id cl_tokenize(void *b, Id va_s) {
  if (!va_s.s) return clNil;
  return cl_string_split(b,
      cl_string_replace(b, cl_string_replace(b, va_s, S("("), S(" ( ")),
      S(")"), S(" ) ")), ' ');
}

int cl_process_number(char *result, char *source) {
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
  if (n > 2 && s[1] == 'x' && s[0] == '0') {
    base = 16;
    s += 2;
  }
  if (n > 2 && s[0] == '0' && s[1] >= '0' && s[1] <= '7' ) {
    base = 8;
    s += 1;
  }
  if (n > 2 && s[1] == 'b' && s[0] == '0') {
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

Id cl_atom(void *b, Id token) {
  CL_ACQUIRE_STR_D(dt, token, clNil);
  char *ep;
  char n[1024];
  int base = cl_process_number((char *)&n, dt.s);
  long l = strtol((char *)&n, &ep, base);
  if (ep && *ep == '\0') return cl_int((int)l);
  float f = strtof(dt.s, &ep);
  if (ep && *ep == '\0') return cl_float(f);
  return cl_intern(token);
}

#define RETURN(v) { rv = v; goto finish; }
Id cl_read_from(void *b, Id tokens) {
  Id rv = clNil;
  int quote = 0;

  cl_reset_errors(b);
  if (!tokens.s) return clNil;
next_token:
  if (cl_ary_len(b, tokens) == 0) 
      return cl_handle_error_with_err_string_nh(__FUNCTION__, 
          "unexpected EOF while reading");
  Id token = cl_ary_unshift(b, tokens);
  if (cl_string_starts_with(b, token, S("'"))) {
    Id word = cl_string_sub_str_new(b, token, 1, -1);
    quote = 1;
    if (cl_string_len(b, word) > 0) {
      token = word; 
    } else {
      goto next_token;
    }
  }
  if (cl_string_equals_cp_i(token, "(")) {
    Id l = cl_ary_new(b);
    while (!cl_string_equals_cp_i(ca_f(tokens), ")")) {
        cl_ary_push(b, l, cl_read_from(b, tokens)); CE(break) }
    cl_ary_unshift(b, tokens);
    RETURN(l);
  } else if (cl_string_equals_cp_i(token, ")")) {
    return cl_handle_error_with_err_string_nh(__FUNCTION__, 
        "unexpected )");
  } else RETURN(cl_atom(b, token));

finish:
  if (quote) {
    Id ql = cl_ary_new(b);
    cl_ary_push(b, ql, cl_intern(S("quote")));
    cl_ary_push(b, ql, rv);
    rv = ql;
  }
  return rv;
}

Id cl_parse(void *b, Id va_s) { 
  return cl_read_from(b, cl_tokenize(b, cl_string_parse(b,
      va_s))); 
}

Id S_icounter;

void cl_perf_count(Id this) {
  if (cl_perf_mode) return;
  void *b = cl_perf;
  cl_ht_inc(b, cl_md->globals, S_icounter);
}


void cl_perf_show() {
  void *b = cl_perf;
  Id n = cl_ht_get(b, cl_md->globals, S_icounter);
  D("n", n);
  cl_garbage_collect(b);
  cl_mem_dump(b);
}

#define cl_eval2(x, e) cl_eval(b, x, e, this, this, 1)
size_t nested_depth = 0;
size_t stack_overflow = 0;
size_t rc_count = 0;
Id cl_begin(void *b, Id x, int start, Id _env, Id this, Id previous);
Id cl_eval(void *b, Id x, Id _env, Id this, Id previous, int last) {
  Id x0, exp, val, var, vars, rv, env;
  nested_depth++;
  if (stack_overflow) return clNil;
  if (nested_depth > 2000) {
    printf("STACKoverflow\n");
    stack_overflow = 1;
  }
  cl_retain(clNil, _env);
  cl_garbage_collect(b);
  Id func_name = clNil;
tail_rc_start:
  val= clNil; vars = clNil; rv = clNil;
  if (!x.s) RETURN(clNil);
  //printf("START: %x %lx\n", CL_ADR(vars), &vars);
  env = (_env.s ? _env : cl_globals);
  if (CL_TYPE(x) == CL_TYPE_SYMBOL) {
    if (cl_string_starts_with(b, x, S(":"))) {
      RETURN(cl_intern(cl_string_sub_str_new(b, x, 1, -1)));
    }
    if (cl_string_equals_cp_i(x, "globals")) RETURN(cl_globals);
    RETURN(cl_env_find(b, env, x));
  } else if (CL_TYPE(x) != CL_TYPE_ARRAY) {
    RETURN(x); // constant literal
  } 
  if (CL_TYPE(x) == CL_TYPE_ARRAY && cl_ary_len(b, x) == 3) {
    Id m = ca_s(x);
    if (CL_TYPE(m) == CL_TYPE_SYMBOL && cl_string_equals_cp_i(m, ".")) {
      Id a = cl_retain(clNil, cl_ary_new(b));
      cl_ary_push(b, a, cl_eval2(ca_f(x), env));
      cl_ary_push(b, a, cl_eval2(ca_th(x), env));
      cl_release(a);
      RETURN(a);
    }
  }
  x0 = ca_f(x);
  if (cl_string_equals_cp_i(x0, "quote")) {
    RETURN(ca_s(x));
  } else if (cl_string_equals_cp_i(x0, "/#")) {
    Id rx = cl_rx_new(cl_ary_join_by_s(b,  
        cl_ary_clone_part(b, x, 1, -1), S(" ")));
    return rx;
  } else if (cl_string_equals_cp_i(x0, "if")) { // (if test conseq alt)
    Id test = ca_s(x), conseq = ca_th(x), alt = ca_fth(x);
    Id t = cl_eval2(test, env);
    RETURN(cnil2(t).s ? cl_eval2(conseq, env) : cl_eval2(alt, env));
  } else if (cl_string_equals_cp_i(x0, "set!")) { // (set! var exp)
    var = ca_s(x), exp = ca_th(x);
    cl_env_find_and_set(b, env, var, cl_eval2(exp, env));
  } else if (cl_string_equals_cp_i(x0, "define")) { // (define var exp)
    var = ca_s(x), exp = ca_th(x);
    RETURN(cl_ht_set(b, env, var, cl_eval2(exp, env)));
  } else if (cl_string_equals_cp_i(x0, "lambda")) { //(lambda (var*) exp)
    Id l = cl_ary_new(b); cl_ary_set_lambda(b, l);
    cl_ary_push(b, l, ca_s(x)); 
    Id c = cl_ary_new(b);
    int i = 2;
    cl_ary_push(b, c, cl_intern(S("begin")));
    Id v;
    while ((v = cl_ary_iterate(b, x, &i)).s) cl_ary_push(b, c, v);
    cl_ary_push(b, l, c); cl_ary_push(b, l, env);
    RETURN(l);
  } else if (cl_string_equals_cp_i(x0, "begin")) {  // (begin exp*)
    RETURN(cl_begin(b, x, 1, env, this, this));
  } else {  // (proc exp*)
    Id v;
    vars = cl_retain(clNil, cl_ary_new(b));
    int i = 1;
    while ((v = cl_ary_iterate(b, x, &i)).s) 
        cl_ary_push(b, vars, cl_eval2(v, env));
    func_name = x0;
    Id lambda = cl_env_find(b, env, func_name);
    if (!lambda.s) { 
      RETURN(cl_handle_error_with_err_string(__FUNCTION__, "Unknown proc", 
          cl_string_ptr(func_name))); 
    }
    if (cl_is_type_i(lambda, CL_TYPE_CFUNC)) {
      RETURN(cl_call(b, lambda, env, vars));
    }
    int tail_rc = 0;
    if (cl_equals_i(func_name, this)) tail_rc = last;
    Id e = tail_rc ? env : cl_env_new(b, cl_ary_index(b, lambda, 2)), p;
    Id vdecl = cl_ary_index(b, lambda, 0);
    if (CL_TYPE(vdecl) == CL_TYPE_ARRAY) {
      if (cl_ary_len(b, vdecl) != cl_ary_len(b, vars))  {
         char es[1024]; 
         snprintf(es, 1023, "Parameter count mismatch! (have %d, expected %d)", 
             cl_ary_len(b, vars), cl_ary_len(b, vdecl));  
         RETURN(cl_handle_error_with_err_string(__FUNCTION__, 
             es, cl_string_ptr(func_name)));
      }
      i = 0;
      while ((p = cl_ary_iterate(b, vdecl, &i)).s) 
          cl_ht_set(b, e, p, cl_ary_index(b, vars, i - 1));
    } else {
      cl_ht_set(b, e, vdecl, vars);
    }
    if (tail_rc) RETURN(clTail);
    Id r =  cl_eval(b, cl_ary_index(b, lambda, 1), e, func_name, this, 0);
    RETURN(r);
  }

finish:
  cl_release(vars);
  if (rv.s == clTail.s && !cl_equals_i(this, previous)) goto tail_rc_start;
  cl_release(_env);
  nested_depth--;
  if (rv.s == clError.s) {
    D("clError", this);
  }
  return rv;
}

Id cl_begin(void *b, Id x, int start, Id env, Id this, Id previous) {
  Id val = clNil, exp;
  int i = start;
  int l = cl_ary_len(b, x);
  while ((exp = cl_ary_iterate(b, x, &i)).s) 
    val = cl_eval(b, exp, env, this, previous, l == i);
  return val;
}

Id  __try_convert_to_floats(void *b, Id x) {
  Id a = cl_ary_new(b), n;
  int i = 0; 
  while ((n = cl_ary_iterate(b, x, &i)).s) {
    if (!cl_is_number(n)) return clNil;
    cl_ary_push(b, a, CL_TYPE(n) == CL_TYPE_INT ? cl_float(CL_INT(n)) : n);
  }
  return a;
}

Id  __try_convert_to_ints(void *b, Id x) {
  Id a = cl_ary_new(b), n0, n;
  int i = 0; 
  while ((n0 = cl_ary_iterate(b, x, &i)).s) {
    n = cn(n0);
    if (!cl_is_number(n)) return clNil;
    cl_ary_push(b, a, n);
  }
  return a;
}

#define ON_I \
  int t = (cl_ary_contains_only_type_i(b, x, CL_TYPE_INT) ? 1 : \
      (cl_ary_contains_only_type_i(b, x, CL_TYPE_FLOAT) ? 2 : 0)); \
  if (t == 0) { \
      Id try = __try_convert_to_ints(b, x);  \
      if (try.s) { t = 1; x = try; }} \
  if (t == 0) { \
      Id try = __try_convert_to_floats(b, x);  \
      if (try.s) { t = 2; x = try; }} \
  int ai = CL_INT(ca_f(x)); int bi = CL_INT(ca_s(x)); \
  float af = CL_FLOAT(ca_f(x)); float bf = CL_FLOAT(ca_s(x)); \
  Id r = clNil; \
  if (t == 1) { 
#define ON_F ; } else if (t == 2) {
#define R  ; } return r;

Id cl_to_string(void *b, Id exp);
#define VB void *b, Id env

Id cl_add(VB, Id x) { ON_I r = cl_int(ai + bi) ON_F r = cl_float(af + bf) R }
Id cl_sub(VB, Id x) { ON_I r = cl_int(ai - bi) ON_F r = cl_float(af - bf) R }
Id cl_mul(VB, Id x) { ON_I r = cl_int(ai * bi) ON_F r = cl_float(af * bf) R }
Id cl_div(VB, Id x) { ON_I r = cl_int(ai / bi) ON_F r = cl_float(af / bf) R }
Id cl_gt(VB, Id x) { ON_I r = cb(ai > bi) ON_F r = cb(af > bf) R }
Id cl_lt(VB, Id x) { ON_I r = cb(ai < bi) ON_F r = cb(af < bf) R }
Id cl_ge(VB, Id x) { ON_I r = cb(ai >= bi) ON_F r = cb(af >= bf) R }
Id cl_le(VB, Id x) { ON_I r = cb(ai <= bi) ON_F r = cb(af <= bf) R }
Id cl_eq(VB, Id x) { return cb(cl_equals_i(ca_f(x), ca_s(x))); }
Id cl_length(VB, Id x) { return cl_int(cl_ary_len(b, x)); }
Id cl_cons(VB, Id x) { Id a = ca_f(x); Id r = cl_ary_new(b); 
    cl_ary_push(b, r, ca_f(a)); cl_ary_push(b, r, ca_s(a)); 
    return r; }
Id cl_car(VB, Id x) { return ca_f(ca_f(x)); }
Id cl_cdr(VB, Id x) { Id a = ca_f(x); return cl_ary_index(b, a, -1); }
Id cl_list(VB, Id x) { return x; }
Id cl_is_list(VB, Id x) { return cb(cl_is_type_i(x, CL_TYPE_ARRAY)); }
Id cl_is_null(VB, Id x) { return cb(cnil(x)); }
Id cl_is_symbol(VB, Id x) { return cb(cl_is_type_i(x, CL_TYPE_SYMBOL)); }
Id cl_display(VB, Id x) { printf("%s", cl_string_ptr(cl_ary_join_by_s(b, 
    cl_ary_map(b, x, cl_to_string), S(" ")))); fflush(stdout); return clNil;}
Id cl_newline(VB, Id x) { printf("\n"); return clNil;}
Id cl_resetline(VB, Id x) { printf("\r"); fflush(stdout); return clNil;}
Id cl_current_ms(VB, Id x) { return cl_int((int)cl_current_time_ms());}
Id __cl_perf_show(VB, Id x) { cl_perf_show();return clNil;}
Id cl_make_hash(VB, Id x) { return cl_ht_new(b); }
Id cl_hash_set(VB, Id x) { return cl_ht_set(b, ca_f(x), ca_s(x), ca_th(x)); }
Id cl_hash_get(VB, Id x) { return cl_ht_get(b, ca_f(x), ca_s(x)); }
Id cl_make_array(VB, Id x) { return cl_ary_new(b); }
Id cl_array_set(VB, Id x) { return cl_ary_set(b, ca_f(x), CL_INT(ca_s(x)), 
    ca_th(x)); }
Id cl_array_get(VB, Id x) { return cl_ary_index(b, ca_f(x), CL_INT(ca_s(x))); }
Id cl_array_push(VB, Id x) { return cl_ary_push(b, ca_f(x), ca_s(x)); }
Id cl_array_pop(VB, Id x) { return cl_ary_pop(b, ca_f(x)); }
Id cl_array_unshift(VB, Id x) { return cl_ary_unshift(b, ca_f(x)); }
Id cl_array_len(VB, Id x) { return cl_int(cl_ary_len(b, ca_f(x))); }
Id cl_string_ref(VB, Id x) { 
    return cl_ary_index(b, string_ref, CL_INT(ca_f(x))); }
Id _cl_string_split(VB, Id x) { 
    return cl_string_split2(b, ca_f(x), ca_s(x)); }

Id cl_array_each(VB, Id x) { 
  Id this = clNil;
  Id e = cl_env_new(b, env);
  Id lambda = ca_s(x);
  Id vdecl, pn;
  int l;
  if (!cl_is_type_i(lambda, CL_TYPE_CFUNC)) {
    vdecl = ca_f(lambda);
    l = cl_ary_len(b, vdecl);
    pn = l > 0 ? ca_f(vdecl) : clNil;
  }
  int i = 0; 
  Id v;
  while ((v = cl_ary_iterate(b, ca_f(x), &i)).s) {
    if (cl_is_type_i(lambda, CL_TYPE_CFUNC)) {
      Id vars = cl_ary_new(b);
      cl_ary_push(b, vars, v);
      cl_call(b, lambda, e, vars);
    } else {
      if (pn.s) cl_ht_set(b, e, pn, v);
      cl_eval(b, ca_s(lambda), e, clNil, clNil, 0);
    }
  }
  return clNil;
}

Id cl_hash_each(VB, Id x) { 
  Id this = clNil;
  Id e = cl_env_new(b, env);
  Id lambda = ca_s(x);
  Id vdecl = ca_f(lambda);
  int l = cl_ary_len(b, vdecl);
  Id pk = l > 0 ? ca_f(vdecl) : clNil;
  Id pv = l > 1 ? ca_s(vdecl) : clNil;

  cl_ht_iterate_t h;
  h.initialized = 0;
  cl_ht_entry_t *hr;
  while ((hr = cl_ht_iterate(b, ca_f(x), &h))) {
    if (pk.s) cl_ht_set(b, e, pk, hr->va_key);
    if (pv.s) cl_ht_set(b, e, pv, hr->va_value);
    cl_eval(b, ca_s(lambda), e, clNil, clNil, 0);
  }
  return clNil;
}
Id _cl_rx_match_string(VB, Id x) { 
  return cb(cl_rx_match(b, ca_f(x), ca_s(x)));
}

void *cl_set_standard_ns = 0;

Id cl_set_namespace(VB, Id x) { 
  Id ns = ca_f(x);
  if (cl_string_equals_cp_i(ns, "heap")) {  // (begin exp*)
    cl_set_standard_ns = cl_heap;
  } else if (cl_string_equals_cp_i(ns, "perf")) {
    cl_set_standard_ns = cl_perf;
  } else {
    printf("Unknown namespace: '%s'\n", cl_string_ptr(cl_to_string(b, x)));
  }
  return clNil;
}

Id cl_rand(VB, Id x) {
  Id n = ca_f(x);
  if (!n.s) n = cl_int(1 << 16);
  return cl_int(rand() % CL_INT(n));
}

Id cl_shl(VB, Id x) { return cl_int(CL_INT(ca_f(x)) << CL_INT(ca_s(x))); }
Id cl_shr(VB, Id x) { return cl_int(CL_INT(ca_f(x)) >> CL_INT(ca_s(x))); }
Id cl_and(VB, Id x) { return cb(!cnil(ca_f(x)) && !cnil(ca_s(x))); }
Id cl_or(VB, Id x) { return cb(!cnil(ca_f(x)) || !cnil(ca_s(x))); }
Id cl_not(VB, Id x) { return cb(cnil(ca_f(x))); }

Id cl_sleep(VB, Id x) { 
    ON_I usleep((size_t)ai * 1000000)
    ON_F usleep((size_t)(af * 1000000.0)) R }

char *cl_std_n[] = {"+", "-", "*", "/", ">", "<", ">=", "<=", "=",
    "equal?", "eq?", "length", "cons", "car", "cdr", "list", "list?", 
    "null?", "symbol?", "display", "newline", "resetline", "current-ms", 
    "perf-show", "make-hash", "hash-set", "hash-get", 
    "make-array", "array-get", "array-set", "array-push", 
    "array-pop", "array-unshift", "array-len", "string-ref", 
    "string-split", "array-each", "hash-each", 
    "rx-match-string", "set-namespace", "rand", 
    "<<", ">>", "and", "or", "not", "sleep", 0};

Id (*cl_std_f[])(void *b, Id, Id) = {cl_add, cl_sub, cl_mul, cl_div, cl_gt, cl_lt, cl_ge, 
    cl_le, cl_eq, cl_eq, cl_eq, cl_length, cl_cons, cl_car, cl_cdr,
    cl_list, cl_is_list, cl_is_null, cl_is_symbol, cl_display,
    cl_newline, cl_resetline, cl_current_ms, __cl_perf_show, 
    cl_make_hash, cl_hash_set, cl_hash_get, cl_make_array,
    cl_array_get, cl_array_set, cl_array_push, cl_array_pop,
    cl_array_unshift, cl_array_len, cl_string_ref, 
    _cl_string_split, cl_array_each, cl_hash_each, 
    _cl_rx_match_string, cl_set_namespace, cl_rand,
    cl_shl, cl_shr, cl_and, cl_or, cl_not, cl_sleep, 0};


void cl_add_std_functions(void *b, Id env) {
  int i = 0;
  while (cl_std_n[i] != 0) { cl_define_func(b, cl_std_n[i], cl_std_f[i], env); i++; }
}

void cl_add_perf_symbols(void *b) {
  S_icounter = IS("icounter");
}

void cl_add_globals(void *b, Id env) {
  cl_add_std_functions(b, env);
}

Id cl_to_inspect(void *b, Id exp) {
  if (CL_TYPE(exp) == CL_TYPE_SYMBOL) {
    Id s = S(":");
    return cl_string_append(b, s, exp);
  }
  return cl_to_string(b, exp);
}

Id cl_to_string(void *b, Id exp) {
  if (CL_TYPE(exp) == CL_TYPE_BOOL) { return S(exp.s ? "true" : "null"); }
  if (cl_is_number(exp)) return cl_string_new_number(b, exp);
  if (CL_TYPE(exp) == CL_TYPE_CFUNC) { 
    Id s = S("CFUNC<");
    cl_cfunc_t *cf; CL_TYPED_VA_TO_PTR(cf, exp, CL_TYPE_CFUNC, clNil);
    cl_string_append(b, s, cl_string_new_hex_number(b, 
        cl_int((long)&cf->func_ptr)));
    cl_string_append(b, s, S(">"));
    return s;
  }
  if (CL_TYPE(exp) == CL_TYPE_SYMBOL) {
    return exp;
  }
  if (CL_TYPE(exp) == CL_TYPE_STRING) {
    Id s = S("\"");
    cl_string_append(b, s, exp);
    cl_string_append(b, s, S("\""));
    return s;
  }
  if (CL_TYPE(exp) == CL_TYPE_REGEXP) {
    Id s = S("(#/ ");
    cl_string_append(b, s, cl_rx_match_string(b, exp));
    cl_string_append(b, s, S(")"));
    return s;
  }
  if (CL_TYPE(exp) == CL_TYPE_ARRAY) {
    if (cl_ary_is_lambda(b, exp)) {
      Id s = S("(lambda ");
      Id vdecl = ca_f(exp);
      if (CL_TYPE(vdecl) == CL_TYPE_ARRAY) {
        cl_string_append(b, s, S("("));
        cl_string_append(b, s, cl_ary_join_by_s(b, cl_ary_map(b, vdecl,
            cl_to_string), S(" ")));
        cl_string_append(b, s, S(")"));
      } else cl_string_append(b, s, vdecl);
      cl_string_append(b, s, S(" ("));
      cl_string_append(b, s, cl_ary_join_by_s(b, cl_ary_map(b, ca_s(exp), 
          cl_to_string), S(" ")));
      cl_string_append(b, s, S("))"));
      return s;
    }
    Id s = S("(");
    cl_string_append(b, s, cl_ary_join_by_s(b, 
        cl_ary_map(b, exp, cl_to_string), S(" ")));
    return cl_string_append(b, s, S(")"));
  }
  if (CL_TYPE(exp) == CL_TYPE_HASH) {
    Id s = S("{");
    cl_string_append(b, s, cl_ary_join_by_s(b, 
        cl_ht_map(b, exp, cl_to_string), S(", ")));
    return cl_string_append(b, s, S("}"));
  }
  if (CL_TYPE(exp) != CL_TYPE_ARRAY) return exp;
}

void cl_repl(void *b, FILE *f, Id filename, int interactive) {
  cl_retain(clNil, filename);
  while (1) {
    stack_overflow = 0;
    nested_depth = 0;
    string_ref = cl_retain(filename, cl_ary_new(b));
    Id parsed = cl_retain(filename, cl_parse(b, 
        cl_input(b, f, interactive, cl_perf_mode ? "perf>" :  "schemejit> ")));
    Id val = cl_eval(b, parsed, cl_globals, filename, clNil, 1);
    cl_release(parsed);
    cl_release(string_ref);
    if (feof(f)) break;
    if (interactive) printf("=> %s\n", cl_string_ptr(cl_to_inspect(b, val)));
    cl_garbage_collect(b);
    //cl_mem_dump(b);
    if (cl_set_standard_ns) {
      b = cl_set_standard_ns;
      cl_set_standard_ns = 0;
    }
  }
  cl_release(filename);
}
