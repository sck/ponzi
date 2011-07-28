/*
 * Scheme parsing code, port of Norvig's lis.py:
 * <http://norvig.com/lispy.html>
 */

#define IS(s) cl_intern(S(s))
Id S_if, S_quote, S_set, S_define, S_lambda, S_begin, S_icounter;

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
  if (dt.l > 1 && dt.s[0] == ':')  {
      return cl_intern(cl_string_sub_str_new(b, token, 1, -1));
  }
  char *ep;
  char n[1024];
  int base = cl_process_number((char *)&n, dt.s);
  long l = strtol((char *)&n, &ep, base);
  if (ep && *ep == '\0') return cl_int((int)l);
  float f = strtof(dt.s, &ep);
  if (ep && *ep == '\0') return cl_float(f);
  return cl_intern(token);
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

#define cl_eval2(x, e) cl_eval(b, x, e, this, 1)
#define RETURN(v) { rv = v; goto finish; }
Id cl_eval(void *b, Id x, Id env, Id this, int last) {
  //cl_perf_count(this);
tail_rc_start:
  cl_retain(env);
  cl_garbage_collect(b);
  Id x0, exp, val= clNil, var, vars = clNil, rv = clNil;
  //printf("START: %x %lx\n", CL_ADR(vars), &vars);
  if (!x.s) RETURN(clNil);
  env = (env.s ? env : cl_globals);
  if (CL_TYPE(x) == CL_TYPE_SYMBOL) {
    RETURN(cl_env_find(b, env, x));
  } else if (CL_TYPE(x) != CL_TYPE_ARRAY) {
    RETURN(x); // constant literal
  } 
  x0 = ca_f(x);
  if (cl_equals_i(x0, S_quote)) {
    RETURN(ca_s(x));
  } else if (cl_equals_i(x0, S_if)) { // (if test conseq alt)
    Id test = ca_s(x), conseq = ca_th(x), alt = ca_fth(x);
    RETURN(cnil2(cl_eval2(test, env)).s ? cl_eval2(conseq, env) : 
        cl_eval2(alt, env));
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
    RETURN(l);
  } else if (cl_equals_i(x0, S_begin)) {  // (begin exp*)
    int i = 1;
    int l = cl_ary_len(b, x);
    while ((exp = cl_ary_iterate(b, x, &i)).s) 
      val = cl_eval(b, exp, env, this, l == i);
    RETURN(val);
  } else {  // (proc exp*)
    Id v;
    vars = cl_retain(cl_ary_new(b));
    //printf("NEW: %x %lx\n", CL_ADR(vars), &vars);
    int i = 1;
    while ((v = cl_ary_iterate(b, x, &i)).s) 
        cl_ary_push(b, vars, cl_eval2(v, env));
    Id func_name = x0;
    Id lambda = cl_env_find(b, env, func_name);
    if (!lambda.s) { 
      RETURN(cl_handle_error_with_err_string(__FUNCTION__, "Unknown proc", 
          cl_string_ptr(b, func_name))); 
    }
    if (cl_is_type_i(lambda, CL_TYPE_CFUNC)) {
      RETURN(cl_call(b, lambda, vars));
    }
    Id vdecl = cl_ary_index(b, lambda, 0);
    if (cl_ary_len(b, vdecl) != cl_ary_len(b, vars))  {
       char es[1024]; 
       snprintf(es, 1023, "Parameter count mismatch! (have %d, expected %d)", 
           cl_ary_len(b, vars), cl_ary_len(b, vdecl));  
       RETURN(cl_handle_error_with_err_string(__FUNCTION__, 
           es, cl_string_ptr(b, func_name)));
    }
    int tail_rc = 0;
    if (cl_equals_i(func_name, this)) tail_rc = last;
    Id e = tail_rc ? env : cl_env_new(b, cl_ary_index(b, lambda, 2)), p;
    i = 0;
    while ((p = cl_ary_iterate(b, vdecl, &i)).s) 
        cl_ht_set(b, e, p, cl_ary_index(b, vars, i - 1));
    if (tail_rc) {
      RETURN(clTail);
    }
    Id r =  cl_eval(b, cl_ary_index(b, lambda, 1), e, func_name, 1);
    if (r.t.d.i == 2) {
      cl_release(vars);
      cl_release(env);
      env = e;
      x = cl_ary_index(b, lambda, 1);
      goto tail_rc_start;
    }
    RETURN(r);
  }

finish:
  cl_release(vars);
  cl_release(env);
  return rv;
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
Id __cl_perf_show(VB, Id x) { cl_perf_show();return clNil;}

char *cl_std_n[] = {"+", "-", "*", "/", "not", ">", "<", ">=", "<=", "=",
    "equal?", "eq?", "length", "cons", "car", "cdr", "list", "list?", 
    "null?", "symbol?", "display", "newline", "resetline", "current-ms", 
    "perf-show", 0};
Id (*cl_std_f[])(void *b, Id) = {cl_add, cl_sub, cl_mul, cl_div, cl_not, cl_gt, cl_lt, cl_ge, 
    cl_le, cl_eq, cl_eq, cl_eq, cl_length, cl_cons, cl_car, cl_cdr,
    cl_list, cl_is_list, cl_is_null, cl_is_symbol, cl_display,
    cl_newline, cl_resetline, cl_current_ms, __cl_perf_show, 0};

void cl_add_perf_symbols(void *b) {
  S_icounter = IS("icounter");
}

void cl_add_globals(void *b, Id env) {
  S_if = IS("if"); S_quote = IS("quote"); S_set = IS("set!");
  S_define = IS("define"); S_lambda = IS("lambda"); S_begin = IS("begin");
  int i = 0;
  while (cl_std_n[i] != 0) { cl_define_func(b, cl_std_n[i], cl_std_f[i], env); i++; }
}

Id cl_to_inspect(void *b, Id exp) {
  if (CL_TYPE(exp) == CL_TYPE_SYMBOL) {
    Id s = S(":");
    return cl_string_append(b, s, exp);
  }
  if (CL_TYPE(exp) == CL_TYPE_STRING) {
    Id s = S("(quote ");
    cl_string_append(b, s, exp);
    return cl_string_append(b, s, S(")"));
  }
  return cl_to_string(b, exp);
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
    Id parsed = cl_retain(cl_parse(b, 
        cl_input(b, f, interactive, cl_perf_mode ? "perf>" :  "schemejit> ")));
    Id val = cl_eval(b, parsed, cl_globals, clNil, 1);
    cl_release(parsed);
    if (feof(f)) return;
    if (interactive) printf("-> %s\n", cl_string_ptr(b, cl_to_inspect(b, val)));
    cl_garbage_collect(b);
    //cl_mem_dump(b);
  }
}
