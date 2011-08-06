/*
 * Scheme parsing code, port of Norvig's lis.py:
 * <http://norvig.com/lispy.html>
 */

#define IS(s) sj_intern(S(s))

Id string_ref;

Id sj_string_parse(void *b, Id s) {
  if (!s.s) return sjNil;
  Id ary = sj_string_split(b, s, '"');
  if (!ary.s) return sjNil;
  int string_mode = 0;
  Id v;
  int i = 0;
  Id r = sj_ary_new(b);
  while ((v = sj_ary_iterate(b, ary, &i)).s) {
    if (!string_mode) {
      sj_ary_push(b, r, v);
    } else {
      sj_ary_push(b, string_ref, v);
      Id sr = S("(string-ref ");
      sj_string_append(b, sr, sj_string_new_number(b, 
          sj_int(sj_ary_len(b, string_ref) - 1)));
      sj_string_append(b, sr, S(")"));
      sj_ary_push(b, r, sr);
    }
    string_mode = 1 - string_mode;
  }
  return sj_ary_join_by_s(b, r, S(""));
}

Id sj_tokenize(void *b, Id va_s) {
  if (!va_s.s) return sjNil;
  return sj_string_split(b,
      sj_string_replace(b, sj_string_replace(b, va_s, S("("), S(" ( ")),
      S(")"), S(" ) ")), ' ');
}

int sj_process_number(char *result, char *source) {
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

Id sj_atom(void *b, Id token) {
  SJ_ACQUIRE_STR_D(dt, token, sjNil);
  char *ep;
  char n[1024];
  int base = sj_process_number((char *)&n, dt.s);
  long l = strtol((char *)&n, &ep, base);
  if (ep && *ep == '\0') return sj_int((int)l);
  float f = strtof(dt.s, &ep);
  if (ep && *ep == '\0') return sj_float(f);
  return sj_intern(sj_to_symbol(token));
}

#define RETURN(v) { rv = v; goto finish; }
Id sj_read_from(void *b, Id tokens) {
  Id rv = sjNil;
  int quote = 0;

  sj_reset_errors(b);
  if (!tokens.s) return sjNil;
next_token:
  if (sj_ary_len(b, tokens) == 0) 
      return sj_handle_error_with_err_string_nh(__FUNCTION__, 
          "unexpected EOF while reading");
  Id token = sj_ary_unshift(b, tokens);
  if (sj_string_starts_with(b, token, S("'"))) {
    Id word = sj_string_sub_str_new(b, token, 1, -1);
    quote = 1;
    if (sj_string_len(b, word) > 0) {
      token = word; 
    } else {
      goto next_token;
    }
  }
  if (sj_string_equals_cp_i(token, "(")) {
    Id l = sj_ary_new(b);
    while (!sj_string_equals_cp_i(ca_f(tokens), ")")) {
        sj_ary_push(b, l, sj_read_from(b, tokens)); CE(break) }
    sj_ary_unshift(b, tokens);
    RETURN(l);
  } else if (sj_string_equals_cp_i(token, ")")) {
    return sj_handle_error_with_err_string_nh(__FUNCTION__, 
        "unexpected )");
  } else RETURN(sj_atom(b, token));

finish:
  if (quote) {
    Id ql = sj_ary_new(b);
    sj_ary_push(b, ql, sj_intern(S("quote")));
    sj_ary_push(b, ql, rv);
    rv = ql;
  }
  return rv;
}

Id sj_parse(void *b, Id va_s) { 
  return sj_read_from(b, sj_tokenize(b, sj_string_parse(b, va_s))); 
}

Id S_icounter;

void sj_perf_count(Id this) {
  if (sj_perf_mode) return;
  void *b = sj_perf;
  sj_ht_inc(b, sj_md->globals, S_icounter);
}


void sj_perf_show() {
  void *b = sj_perf;
  Id n = sj_ht_get(b, sj_md->globals, S_icounter);
  D("n", n);
  sj_garbage_collect(b);
  sj_mem_dump(b);
}

#define DC2B(va) sj_deep_copy(b, sj_perf, va)
#define DC2P(va) sj_deep_copy(sj_perf, b, va)
#define sj_eval2(x, e, l) sj_eval(b, x, e, this, this, l)
size_t nested_depth = 0;
size_t stack_overflow = 0;
size_t rc_count = 0;
Id sj_begin(void *b, Id x, int start, Id _env, Id this, Id previous);
Id sj_eval(void *b, Id x, Id _env, Id this, Id previous, int last) {
  //printf("sj_eval: %s %d\n", sj_string_ptr(this), last);
  Id x0, exp, val, var, vars, rv, env;
  nested_depth++;
  if (stack_overflow) return sjNil;
  if (nested_depth > 2000) {
    printf("STACKoverflow\n");
    stack_overflow = 1;
  }
  sj_retain(sjNil, _env);
  sj_garbage_collect(b);
  Id func_name = sjNil;
tail_rc_start:
  val= sjNil; vars = sjNil; rv = sjNil;
  if (!x.s) RETURN(sjNil);
  //printf("START: %x %lx\n", SJ_ADR(vars), &vars);
  env = (_env.s ? _env : sj_globals);
  if (SJ_TYPE(x) == SJ_TYPE_SYMBOL) {
    if (sj_string_starts_with(b, x, S(":"))) {
      RETURN(sj_intern(sj_to_symbol(sj_string_sub_str_new(b, x, 1, -1))));
    }
    if (sj_string_equals_cp_i(x, "globals")) RETURN(sj_globals);
    RETURN(sj_env_find(b, env, x));
  } else if (SJ_TYPE(x) != SJ_TYPE_ARRAY) {
    RETURN(x); // constant literal
  } 
  if (SJ_TYPE(x) == SJ_TYPE_ARRAY && sj_ary_len(b, x) == 3) {
    Id m = ca_s(x);
    if (SJ_TYPE(m) == SJ_TYPE_SYMBOL && sj_string_equals_cp_i(m, ".")) {
      Id a = sj_retain(sjNil, sj_ary_new(b));
      sj_ary_push(b, a, sj_eval2(ca_f(x), env, 0));
      sj_ary_push(b, a, sj_eval2(ca_th(x), env, 1));
      sj_release(a);
      RETURN(a);
    }
  }
  x0 = ca_f(x);
  if (sj_string_equals_cp_i(x0, "quote")) {
    RETURN(ca_s(x));
  } else if (sj_string_equals_cp_i(x0, "/#")) { // (/# ^regexp$)
    Id rx = sj_rx_new(sj_ary_join_by_s(b,  
        sj_ary_clone_part(b, x, 1, -1), S(" ")));
    return rx;
  } else if (sj_string_equals_cp_i(x0, "if")) { // (if test conseq alt)
    Id test = ca_s(x), conseq = ca_th(x), alt = ca_fth(x);
    Id t = sj_eval2(test, env, 0);
    RETURN(cnil2(t).s ? sj_eval2(conseq, env, 1) : sj_eval2(alt, env, 1));
  } else if (sj_string_equals_cp_i(x0, "set!")) { // (set! var exp)
    var = ca_s(x), exp = ca_th(x);
    sj_env_find_and_set(b, env, var, sj_eval2(exp, env, 0));
  } else if (sj_string_equals_cp_i(x0, "define")) { // (define var exp)
    var = ca_s(x), exp = ca_th(x);
    RETURN(sj_ht_set(b, env, var, sj_eval2(exp, env, 1)));
  } else if (sj_string_equals_cp_i(x0, "lambda")) { //(lambda (var*) exp)
    Id l = sj_ary_new(b); sj_ary_set_lambda(b, l);
    sj_ary_push(b, l, ca_s(x)); 
    Id c = sj_ary_new(b);
    int i = 2;
    sj_ary_push(b, c, sj_intern(sj_to_symbol(S("begin"))));
    Id v;
    while ((v = sj_ary_iterate(b, x, &i)).s) sj_ary_push(b, c, v);
    sj_ary_push(b, l, c); sj_ary_push(b, l, env);
    RETURN(l);
  } else if (sj_string_equals_cp_i(x0, "begin")) {  // (begin exp*)
    RETURN(sj_begin(b, x, 1, env, this, this));
  } else if (sj_string_equals_cp_i(x0, "begin-perf")) {  // (begin-perf exp*)
    if (b == sj_perf) return sjNil;
    RETURN(DC2B(sj_begin(sj_perf, DC2P(x), 1, 
        env.s == sj_globals.s ? sjNil : DC2P(env), //DC2P(env), 
        DC2P(this), DC2P(this))));
  } else {  // (proc exp*)
    Id v;
    vars = sj_retain(sjNil, sj_ary_new(b));
    int i = 1;
    while ((v = sj_ary_iterate(b, x, &i)).s) 
        sj_ary_push(b, vars, sj_eval2(v, env, 0));
    func_name = x0;
    Id lambda = sj_env_find(b, env, func_name);
    //D("func_name", func_name);
    if (!lambda.s) { 
      RETURN(sj_handle_error_with_err_string(__FUNCTION__, "Unknown proc", 
          sj_string_ptr(sj_to_string(b, func_name)))); 
    }
    if (sj_is_type_i(lambda, SJ_TYPE_CFUNC)) {
      RETURN(sj_call(b, lambda, env, vars));
    }
    int tail_rc = 0;
    if (sj_equals_i(func_name, this)) tail_rc = last;
    Id e = tail_rc ? env : sj_env_new(b, sj_ary_index(b, lambda, 2)), p;
    Id vdecl = sj_ary_index(b, lambda, 0);
    if (SJ_TYPE(vdecl) == SJ_TYPE_ARRAY) {
      if (sj_ary_len(b, vdecl) != sj_ary_len(b, vars))  {
         char es[1024]; 
         snprintf(es, 1023, "Parameter count mismatch! (have %d, expected %d)", 
             sj_ary_len(b, vars), sj_ary_len(b, vdecl));  
         RETURN(sj_handle_error_with_err_string(__FUNCTION__, 
             es, sj_string_ptr(func_name)));
      }
      i = 0;
      while ((p = sj_ary_iterate(b, vdecl, &i)).s) 
          sj_ht_set(b, e, p, sj_ary_index(b, vars, i - 1));
    } else {
      sj_ht_set(b, e, vdecl, vars);
    }
    if (tail_rc) RETURN(sjTail);
    Id r =  sj_eval(b, sj_ary_index(b, lambda, 1), e, func_name, this, 0);
    RETURN(r);
  }

finish:
  sj_release(vars);
  if (rv.s == sjTail.s && !sj_equals_i(this, previous)) { goto tail_rc_start; }
  sj_release(_env);
  nested_depth--;
  if (rv.s == sjError.s) { D("sjError", this); }
  return rv;
}

Id sj_begin(void *b, Id x, int start, Id env, Id this, Id previous) {
  Id val = sjNil, exp;
  int i = start;
  int l = sj_ary_len(b, x);
  sj_retain(this, this);
  sj_retain(this, previous);
  sj_retain(x, env);
  sj_retain(this, x);
  while ((exp = sj_ary_iterate(b, x, &i)).s) 
    val = sj_eval(b, exp, env, this, previous, l == i);
  sj_release(this);
  sj_release(previous);
  sj_release(x);
  sj_release(env);
  return val;
}

Id  __try_convert_to_floats(void *b, Id x) {
  Id a = sj_ary_new(b), n;
  int i = 0; 
  while ((n = sj_ary_iterate(b, x, &i)).s) {
    if (!sj_is_number(n)) return sjNil;
    sj_ary_push(b, a, SJ_TYPE(n) == SJ_TYPE_INT ? sj_float(SJ_INT(n)) : n);
  }
  return a;
}

Id  __try_convert_to_ints(void *b, Id x) {
  Id a = sj_ary_new(b), n0, n;
  int i = 0; 
  while ((n0 = sj_ary_iterate(b, x, &i)).s) {
    n = cn(n0);
    if (!sj_is_number(n)) return sjNil;
    sj_ary_push(b, a, n);
  }
  return a;
}

#define ON_I \
  int t = (sj_ary_contains_only_type_i(b, x, SJ_TYPE_INT) ? 1 : \
      (sj_ary_contains_only_type_i(b, x, SJ_TYPE_FLOAT) ? 2 : 0)); \
  if (t == 0) { \
      Id try = __try_convert_to_ints(b, x);  \
      if (try.s) { t = 1; x = try; }} \
  if (t == 0) { \
      Id try = __try_convert_to_floats(b, x);  \
      if (try.s) { t = 2; x = try; }} \
  int ai = SJ_INT(ca_f(x)); int bi = SJ_INT(ca_s(x)); \
  float af = SJ_FLOAT(ca_f(x)); float bf = SJ_FLOAT(ca_s(x)); \
  Id r = sjNil; \
  if (t == 1) { 
#define ON_F ; } else if (t == 2) {
#define R  ; } return r;

Id sj_to_string(void *b, Id exp);
#define VB void *b, Id env

Id sj_add(VB, Id x) { ON_I r = sj_int(ai + bi) ON_F r = sj_float(af + bf) R }
Id sj_sub(VB, Id x) { ON_I r = sj_int(ai - bi) ON_F r = sj_float(af - bf) R }
Id sj_mul(VB, Id x) { ON_I r = sj_int(ai * bi) ON_F r = sj_float(af * bf) R }
Id sj_div(VB, Id x) { ON_I r = sj_int(ai / bi) ON_F r = sj_float(af / bf) R }
Id sj_gt(VB, Id x) { ON_I r = cb(ai > bi) ON_F r = cb(af > bf) R }
Id sj_lt(VB, Id x) { ON_I r = cb(ai < bi) ON_F r = cb(af < bf) R }
Id sj_ge(VB, Id x) { ON_I r = cb(ai >= bi) ON_F r = cb(af >= bf) R }
Id sj_le(VB, Id x) { ON_I r = cb(ai <= bi) ON_F r = cb(af <= bf) R }
Id sj_eq(VB, Id x) { return cb(sj_equals_i(ca_f(x), ca_s(x))); }
Id sj_length(VB, Id x) { return sj_int(sj_ary_len(b, x)); }
Id sj_cons(VB, Id x) { Id a = ca_f(x); Id r = sj_ary_new(b); 
    sj_ary_push(b, r, ca_f(a)); sj_ary_push(b, r, ca_s(a)); 
    return r; }
Id sj_car(VB, Id x) { return ca_f(ca_f(x)); }
Id sj_cdr(VB, Id x) { Id a = ca_f(x); return sj_ary_index(b, a, -1); }
Id sj_list(VB, Id x) { return x; }
Id sj_is_list(VB, Id x) { return cb(sj_is_type_i(x, SJ_TYPE_ARRAY)); }
Id sj_is_null(VB, Id x) { return cb(cnil(x)); }
Id sj_is_symbol(VB, Id x) { return cb(sj_is_type_i(x, SJ_TYPE_SYMBOL)); }
Id sj_display(VB, Id x) { printf("%s", sj_string_ptr(sj_ary_join_by_s(b, 
    sj_ary_map(b, x, sj_to_string), S(" ")))); fflush(stdout); return sjNil;}
Id sj_newline(VB, Id x) { printf("\n"); return sjNil;}
Id sj_resetline(VB, Id x) { printf("\r"); fflush(stdout); return sjNil;}
Id sj_current_ms(VB, Id x) { return sj_int((int)sj_current_time_ms());}
Id __sj_perf_show(VB, Id x) { sj_perf_show();return sjNil;}
Id sj_make_hash(VB, Id x) { return sj_ht_new(b); }
Id sj_hash_set(VB, Id x) { return sj_ht_set(b, ca_f(x), ca_s(x), ca_th(x)); }
Id sj_hash_get(VB, Id x) { return sj_ht_get(b, ca_f(x), ca_s(x)); }
Id sj_make_array(VB, Id x) { return sj_ary_new(b); }
Id sj_array_set(VB, Id x) { return sj_ary_set(b, ca_f(x), SJ_INT(ca_s(x)), 
    ca_th(x)); }
Id sj_array_get(VB, Id x) { return sj_ary_index(b, ca_f(x), SJ_INT(ca_s(x))); }
Id sj_array_push(VB, Id x) { return sj_ary_push(b, ca_f(x), ca_s(x)); }
Id sj_array_pop(VB, Id x) { return sj_ary_pop(b, ca_f(x)); }
Id sj_array_unshift(VB, Id x) { return sj_ary_unshift(b, ca_f(x)); }
Id sj_array_len(VB, Id x) { return sj_int(sj_ary_len(b, ca_f(x))); }
Id sj_string_ref(VB, Id x) { 
    return sj_ary_index(b, string_ref, SJ_INT(ca_f(x))); }
Id _sj_string_split(VB, Id x) { 
    return sj_string_split2(b, ca_f(x), ca_s(x)); }

Id sj_array_each(VB, Id x) { 
  Id this = sjNil;
  Id e = sj_env_new(b, env);
  Id lambda = ca_s(x);
  Id vdecl, pn;
  int l;
  if (!sj_is_type_i(lambda, SJ_TYPE_CFUNC)) {
    vdecl = ca_f(lambda);
    l = sj_ary_len(b, vdecl);
    pn = l > 0 ? ca_f(vdecl) : sjNil;
  }
  int i = 0; 
  Id v;
  while ((v = sj_ary_iterate(b, ca_f(x), &i)).s) {
    if (sj_is_type_i(lambda, SJ_TYPE_CFUNC)) {
      Id vars = sj_ary_new(b);
      sj_ary_push(b, vars, v);
      sj_call(b, lambda, e, vars);
    } else {
      if (pn.s) sj_ht_set(b, e, pn, v);
      sj_eval(b, ca_s(lambda), e, sjNil, sjNil, 0);
    }
  }
  return sjNil;
}

Id sj_hash_each(VB, Id x) { 
  Id this = sjNil;
  Id e = sj_env_new(b, env);
  Id lambda = ca_s(x);
  Id vdecl = ca_f(lambda);
  int l = sj_ary_len(b, vdecl);
  Id pk = l > 0 ? ca_f(vdecl) : sjNil;
  Id pv = l > 1 ? ca_s(vdecl) : sjNil;

  sj_ht_iterate_t h;
  h.initialized = 0;
  sj_ht_entry_t *hr;
  while ((hr = sj_ht_iterate(b, ca_f(x), &h))) {
    if (pk.s) sj_ht_set(b, e, pk, hr->va_key);
    if (pv.s) sj_ht_set(b, e, pv, hr->va_value);
    sj_eval(b, ca_s(lambda), e, sjNil, sjNil, 0);
  }
  return sjNil;
}
Id _sj_rx_match_string(VB, Id x) { 
  return cb(sj_rx_match(b, ca_f(x), ca_s(x)));
}

Id sj_rand(VB, Id x) {
  Id n = ca_f(x);
  if (!n.s) n = sj_int(1 << 16);
  return sj_int(rand() % SJ_INT(n));
}

Id sj_shl(VB, Id x) { return sj_int(SJ_INT(ca_f(x)) << SJ_INT(ca_s(x))); }
Id sj_shr(VB, Id x) { return sj_int(SJ_INT(ca_f(x)) >> SJ_INT(ca_s(x))); }
Id sj_b_or(VB, Id x) { return sj_int(SJ_INT(ca_f(x)) | SJ_INT(ca_s(x))); }
Id sj_b_and(VB, Id x) { return sj_int(SJ_INT(ca_f(x)) & SJ_INT(ca_s(x))); }
Id sj_b_xor(VB, Id x) { return sj_int(SJ_INT(ca_f(x)) ^ SJ_INT(ca_s(x))); }

Id sj_and(VB, Id x) { return cb(!cnil(ca_f(x)) && !cnil(ca_s(x))); }
Id sj_or(VB, Id x) { return cb(!cnil(ca_f(x)) || !cnil(ca_s(x))); }
Id sj_not(VB, Id x) { return cb(cnil(ca_f(x))); }


Id sj_sleep(VB, Id x) { 
    ON_I usleep((size_t)ai * 1000000)
    ON_F usleep((size_t)(af * 1000000.0)) R }

Id sj_type_of(VB, Id x) { return S(sj_type_to_cp(SJ_TYPE(ca_f(x)))); }

char *sj_std_n[] = {"+", "-", "*", "/", ">", "<", ">=", "<=", "=",
    "equal?", "eq?", "length", "cons", "car", "cdr", "list", "list?", 
    "null?", "symbol?", "display", "newline", "resetline", "current-ms",
    "perf-show", "make-hash", "hash-set!", "hash-get", "make-array",
    "array-get", "array-set!", "array-push", "array-pop", "array-unshift",
    "array-len", "string-ref", "string-split", "array-each", "hash-each",
    "rx-match-string", "rand", "<<", ">>", "and", "or", "not", "sleep",
    "|", "&", "^", "type-of", 0};

Id (*sj_std_f[])(void *b, Id, Id) = {sj_add, sj_sub, sj_mul, sj_div, 
    sj_gt, sj_lt, sj_ge, sj_le, sj_eq, sj_eq, sj_eq, sj_length, sj_cons,
    sj_car, sj_cdr, sj_list, sj_is_list, sj_is_null, sj_is_symbol,
    sj_display, sj_newline, sj_resetline, sj_current_ms, __sj_perf_show,
    sj_make_hash, sj_hash_set, sj_hash_get, sj_make_array, sj_array_get,
    sj_array_set, sj_array_push, sj_array_pop, sj_array_unshift,
    sj_array_len, sj_string_ref, _sj_string_split, sj_array_each,
    sj_hash_each, _sj_rx_match_string, sj_rand, sj_shl, sj_shr, sj_and,
    sj_or, sj_not, sj_sleep, sj_b_or, sj_b_and, sj_b_xor, sj_type_of, 0};


void sj_add_std_functions(void *b, Id env) {
  int i = 0;
  while (sj_std_n[i] != 0) { sj_define_func(b, sj_std_n[i], sj_std_f[i], env); i++; }
}

void sj_add_perf_symbols(void *b) {
  S_icounter = IS("icounter");
}

void sj_add_globals(void *b, Id env) {
  sj_add_std_functions(b, env);
}

Id sj_to_inspect(void *b, Id exp) {
  if (SJ_TYPE(exp) == SJ_TYPE_SYMBOL) {
    Id s = S(":");
    return sj_string_append(b, s, exp);
  }
  return sj_to_string(b, exp);
}

Id sj_to_string(void *b, Id exp) {
  int t = SJ_TYPE(exp);
  if (t == SJ_TYPE_BOOL) { return S(exp.s ? "#t" : "#f"); }
  if (sj_is_number(exp)) return sj_string_new_number(b, exp);
  if (t == SJ_TYPE_CFUNC) { 
    Id s = S("CFUNC<");
    sj_cfunc_t *cf; SJ_TYPED_VA_TO_PTR(cf, exp, SJ_TYPE_CFUNC, sjNil);
    sj_string_append(b, s, sj_string_new_hex_number(b, 
        sj_int((long)&cf->func_ptr)));
    sj_string_append(b, s, S(">"));
    return s;
  }
  Id st = sj_string_new_0(b);
  if ((t == SJ_TYPE_SYMBOL || t == SJ_TYPE_STRING) &&
      sj_is_interned(b, exp)) sj_string_append(b, st, S("<I>"));

  if (SJ_TYPE(exp) == SJ_TYPE_SYMBOL) {
    sj_string_append(b, st, S(":"));
    sj_string_append(b, st, exp);
    return st;
  }
  if (SJ_TYPE(exp) == SJ_TYPE_STRING) {
    sj_string_append(b, st, S("\""));
    sj_string_append(b, st, exp);
    sj_string_append(b, st, S("\""));
    return st;
  }
  if (SJ_TYPE(exp) == SJ_TYPE_REGEXP) {
    Id s = S("(#/ ");
    sj_string_append(b, s, sj_rx_match_string(b, exp));
    sj_string_append(b, s, S(")"));
    return s;
  }
  if (SJ_TYPE(exp) == SJ_TYPE_ARRAY) {
    if (sj_ary_is_lambda(b, exp)) {
      Id s = S("(lambda ");
      Id vdecl = ca_f(exp);
      if (SJ_TYPE(vdecl) == SJ_TYPE_ARRAY) {
        sj_string_append(b, s, S("("));
        sj_string_append(b, s, sj_ary_join_by_s(b, sj_ary_map(b, vdecl,
            sj_to_string), S(" ")));
        sj_string_append(b, s, S(")"));
      } else sj_string_append(b, s, vdecl);
      sj_string_append(b, s, S(" ("));
      sj_string_append(b, s, sj_ary_join_by_s(b, sj_ary_map(b, ca_s(exp), 
          sj_to_string), S(" ")));
      sj_string_append(b, s, S("))"));
      return s;
    }
    Id s = S("(");
    sj_string_append(b, s, sj_ary_join_by_s(b, 
        sj_ary_map(b, exp, sj_to_string), S(" ")));
    return sj_string_append(b, s, S(")"));
  }
  if (SJ_TYPE(exp) == SJ_TYPE_HASH) {
    Id s = S("{");
    sj_string_append(b, s, sj_ary_join_by_s(b, 
        sj_ht_map(b, exp, sj_to_string), S(", ")));
    return sj_string_append(b, s, S("}"));
  }
  if (SJ_TYPE(exp) != SJ_TYPE_ARRAY) return exp;
}

void sj_repl(void *b, FILE *f, Id filename, int interactive) {
  sj_retain(sjNil, filename);
  while (1) {
    stack_overflow = 0;
    nested_depth = 0;
    string_ref = sj_retain(filename, sj_ary_new(b));
    Id parsed = sj_retain(filename, sj_parse(b, 
        sj_input(b, f, interactive, sj_perf_mode ? "perf>" :  "schemejit> ")));
    Id val = sj_eval(b, parsed, sj_globals, filename, sjNil, 1);
    sj_release(parsed);
    sj_release(string_ref);
    if (feof(f)) break;
    if (interactive) printf("===> %s\n", sj_string_ptr(sj_to_inspect(b, val)));
    sj_garbage_collect_full(b);
    //sj_mem_dump(b);
  }
  sj_release(filename);
}
