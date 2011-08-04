
Id sj_debug() { 
}
#define D(c, va) __d(b, __FUNCTION__, __LINE__, c, va)

Id sj_to_string(void *b, Id exp);

// DEBUG
Id __ds(void *b, const char *comment, Id va) {
  char bd[SJ_CELL_SIZE * 2];
  snprintf(bd, 1023, "%s%s", comment, strlen(comment) > 0 ? " " : "");
  if (!sj_is_string(va) && SJ_TYPE(va) != SJ_TYPE_ARRAY)  {
    snprintf(bd + strlen(bd), 1023, "%s:", sj_type_to_cp(SJ_TYPE(va)));
    if (!sj_is_number(va)) snprintf(bd + strlen(bd), 1023, "<0x%X> ", SJ_ADR(va));
  }
  Id s = sj_to_string(b, va);
  snprintf(bd + strlen(bd), SJ_CELL_SIZE, "%s", sj_string_ptr(s));
  return S(bd);
}

Id __d(void *b, const char *where, int l, const char *comment, Id va) {
  printf("%lx [%s:%d] %s\n", (size_t)b, where, l, sj_string_ptr(__ds(b, comment, va))); 
  return va; 
}

