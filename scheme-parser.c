/*
 * Scheme parsing code, port of Norvig's lis.py:
 * <http://norvig.com/lispy.html>
 */

#define IS(s) cl_intern(b, S(s))
Id S_if, S_quote, S_set, S_define, S_lambda, S_begin;

Id cl_tokenize(void *b, Id va_s) {
  if (!va_s.s) return clNil;
  return cl_string_split(b,
      cl_string_replace(b, cl_string_replace(b, va_s, S("("), S(" ( ")),
      S(")"), S(" ) ")));
}

Id cl_atom(void *b, Id token) {
  CL_ACQUIRE_STR_D(dt, token, clNil);
  char *ep;
  long l = strtol(dt.s, &ep, 10);
  if (ep && *ep == '\0') return cl_int((int)l);
  float f = strtof(dt.s, &ep);
  if (ep && *ep == '\0') return cl_float(f);
  return cl_intern(b, token);
}

Id cl_read_from(void *b, Id tokens) {
  cl_reset_errors(b);
  if (!tokens.s) return clNil;
  if (cl_ary_len(b, tokens) == 0) 
      return cl_handle_error_with_err_string_nh(__FUNCTION__, 
          "unexpected EOF while reading");
  Id token = cl_ary_unshift(b, tokens);
  if (cl_string_equals_cp_i(token, "(")) {
    Id l = cl_ary_new(b);
    while (!cl_string_equals_cp_i(ca_f(tokens), ")")) {
        cl_ary_push(b, l, cl_read_from(b, tokens)); CE(break) }
    cl_ary_unshift(b, tokens);
    return l;
  } else if (cl_string_equals_cp_i(token, ")")) {
    return cl_handle_error_with_err_string_nh(__FUNCTION__, 
        "unexpected )");
  } else return cl_atom(b, token);
  return clNil;
}

Id cl_parse(void *b, Id va_s) { return cl_read_from(b, cl_tokenize(b, va_s)); }

#define cl_eval2(x, e) cl_eval(b, x, e, this, 1)
Id cl_eval(void *b, Id x, Id env, Id this, int last) {
  //D("x", x);
tail_rc_start:
  if (!x.s) return clNil;
  env = (env.s ? env : cl_global_env);
  if (CL_TYPE(x) == CL_TYPE_SYMBOL) {
    return cl_env_find(b, env, x);
  } else if (CL_TYPE(x) != CL_TYPE_ARRAY) {
    return x; // constant literal
  } 
  Id x0 = ca_f(x), exp, val= clNil, var;
  if (cl_equals_i(x0, S_quote)) {
    return ca_s(x);
  } else if (cl_equals_i(x0, S_if)) { // (if test conseq alt)
    Id test = ca_s(x), conseq = ca_th(x), alt = ca_fth(x);
    return cnil2(cl_eval2(test, env)).s ? cl_eval2(conseq, env) : 
        cl_eval2(alt, env);
  } else if (cl_equals_i(x0, S_set)) { // (set! var exp)
    var = ca_s(x), exp = ca_th(x);
    cl_env_find_and_set(b, env, var, cl_eval2(exp, env));
  } else if (cl_equals_i(x0, S_define)) { // (define var exp)
    var = ca_s(x), exp = ca_th(x);
    cl_ht_set(b, env, var, cl_eval2(exp, env));
  } else if (cl_equals_i(x0, S_lambda)) { //(lambda (var*) exp)
    Id l = cl_ary_new(b); 
    cl_ary_push(b, l, ca_s(x)); cl_ary_push(b, l, ca_th(x));
    cl_ary_push(b, l, env);
    return l; 
  } else if (cl_equals_i(x0, S_begin)) {  // (begin exp*)
    int i = 1;
    int l = cl_ary_len(b, x);
    while ((exp = cl_ary_iterate(b, x, &i)).s) 
      val = cl_eval(b, exp, env, this, l == i);
    return val;
  } else {  // (proc exp*)
    Id vars = cl_ary_new(b), v;
    int i = 1;
    while ((v = cl_ary_iterate(b, x, &i)).s) 
        cl_ary_push(b, vars, cl_eval2(v, env));
    Id func_name = x0;
    Id lambda = cl_env_find(b, env, func_name);
    if (!lambda.s) { return cl_handle_error_with_err_string(__FUNCTION__, 
            "Unknown proc", cl_string_ptr(b, func_name)); }
    if (cl_is_type_i(lambda, CL_TYPE_CFUNC)) return cl_call(b, lambda, vars);
    Id vdecl = cl_ary_index(b, lambda, 0);
    if (cl_ary_len(b, vdecl) != cl_ary_len(b, vars))  {
       char es[1024]; 
       snprintf(es, 1023, "Parameter count mismatch! (have %d, expected %d)", 
           cl_ary_len(b, vars), cl_ary_len(b, vdecl));  
        return cl_handle_error_with_err_string(__FUNCTION__, 
            es, cl_string_ptr(b, func_name));
    }
    int tail_rc = 0;
    // XXX: need to return?
    if (cl_equals_i(func_name, this)) tail_rc = last;
    Id e = tail_rc ? env : cl_env_new(b, cl_ary_index(b, lambda, 2)), p;
    i = 0;
    while ((p = cl_ary_iterate(b, vdecl, &i)).s) 
        cl_ht_set(b, e, p, cl_ary_index(b, vars, i - 1));
    if (tail_rc) {
      return clTail;
    }
    Id r =  cl_eval(b, cl_ary_index(b, lambda, 1), e, func_name, 1);
    if (r.t.d.i == 2) {
      env = e;
      x = cl_ary_index(b, lambda, 1);
      goto tail_rc_start;
    }
    return r;
  }
  return clNil;
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
#define VB void *b

Id cl_add(VB, Id x) { ON_I r = cl_int(ai + bi) ON_F r = cl_float(af + bf) R }
Id cl_sub(VB, Id x) { ON_I r = cl_int(ai - bi) ON_F r = cl_float(af - bf) R }
Id cl_mul(VB, Id x) { ON_I r = cl_int(ai * bi) ON_F r = cl_float(af * bf) R }
Id cl_div(VB, Id x) { ON_I r = cl_int(ai / bi) ON_F r = cl_float(af / bf) R }
Id cl_not(VB, Id x) { ON_I r = cl_int(ai ^ bi) R }
Id cl_gt(VB, Id x) { ON_I r = cb(ai > bi) ON_F r = cb(af > bf) R }
Id cl_lt(VB, Id x) { ON_I r = cb(ai < bi) ON_F r = cb(af < bf) R }
Id cl_ge(VB, Id x) { ON_I r = cb(ai >= bi) ON_F r = cb(af >= bf) R }
Id cl_le(VB, Id x) { ON_I r = cb(ai <= bi) ON_F r = cb(af <= bf) R }
Id cl_eq(VB, Id x) { return cb(cl_equals_i(ca_f(x), ca_s(x))); }
Id cl_length(VB, Id x) { return cl_int(cl_ary_len(b, x)); }
Id cl_cons(VB, Id x) { return cl_ary_new_join(b, ca_f(x), ca_s(x)); }
Id cl_car(VB, Id x) { return ca_f(ca_f(x)); }
Id cl_cdr(VB, Id x) { Id c = cl_ary_clone(b, ca_f(x)); cl_ary_unshift(b, c); return c; }
Id cl_list(VB, Id x) { return x; }
Id cl_is_list(VB, Id x) { return cb(cl_is_type_i(x, CL_TYPE_ARRAY)); }
Id cl_is_null(VB, Id x) { return cb(cnil(x)); }
Id cl_is_symbol(VB, Id x) { return cb(cl_is_type_i(x, CL_TYPE_SYMBOL)); }
Id cl_display(VB, Id x) { printf("%s", cl_string_ptr(b, cl_ary_join_by_s(b, 
    cl_ary_map(b, x, cl_to_string), S(" ")))); fflush(stdout); return clNil;}
Id cl_newline(VB, Id x) { printf("\n"); return clNil;}
Id cl_resetline(VB, Id x) { printf("\r"); fflush(stdout); return clNil;}
Id cl_current_ms(VB, Id x) { return cl_int((int)cl_current_time_ms());}

char *cl_std_n[] = {"+", "-", "*", "/", "not", ">", "<", ">=", "<=", "=",
    "equal?", "eq?", "length", "cons", "car", "cdr", "list", "list?", 
    "null?", "symbol?", "display", "newline", "resetline", "current-ms", 0};
Id (*cl_std_f[])(void *b, Id) = {cl_add, cl_sub, cl_mul, cl_div, cl_not, cl_gt, cl_lt, cl_ge, 
    cl_le, cl_eq, cl_eq, cl_eq, cl_length, cl_cons, cl_car, cl_cdr,
    cl_list, cl_is_list, cl_is_null, cl_is_symbol, cl_display,
    cl_newline, cl_resetline, cl_current_ms, 0};


void cl_add_globals(void *b, Id env) {
  S_if = IS("if"); S_quote = IS("quote"); S_set = IS("set!");
  S_define = IS("define"); S_lambda = IS("lambda"); S_begin = IS("begin");
  int i = 0;
  while (cl_std_n[i] != 0) { cl_define_func(b, cl_std_n[i], cl_std_f[i], env); i++; }
}

Id cl_to_string(void *b, Id exp) {
  if (CL_TYPE(exp) == CL_TYPE_BOOL) { return S(exp.s ? "true" : "null"); }
  if (cl_is_number(exp)) return cl_string_new_number(b, exp);
  if (CL_TYPE(exp) == CL_TYPE_CFUNC) return S("CFUNC");
  if (CL_TYPE(exp) != CL_TYPE_ARRAY) return exp;
  Id s = S("[ ");
  cl_string_append(b, s, cl_ary_join_by_s(b, 
      cl_ary_map(b, exp, cl_to_string), S(" ")));
  return cl_string_append(b, s, S(" ]"));
}

void cl_repl(void *b, FILE *f, int interactive) {
  while (1) {
    Id val = cl_eval(b, cl_parse(b, 
        cl_input(b, f, interactive, "schemejit> ")), cl_global_env, clNil, 1);
    if (feof(f)) return;
    if (interactive) printf("-> %s\n", cl_string_ptr(b, cl_to_string(b, val)));
    cl_garbage_collect(b);
  }
}
