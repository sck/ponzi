
Id pz_debug() { 
}
#define D(c, va) __d(b, __FUNCTION__, __LINE__, c, va)

Id pz_to_string(void *b, Id exp);

// DEBUG
Id __ds(void *b, const char *comment, Id va) {
  char bd[PZ_CELL_SIZE * 2];
  snprintf(bd, 1023, "%s%s", comment, strlen(comment) > 0 ? " " : "");
  if (!pz_is_string(va) && PZ_TYPE(va) != PZ_TYPE_ARRAY)  {
    snprintf(bd + strlen(bd), 1023, "%s:", pz_type_to_cp(PZ_TYPE(va)));
    if (!pz_is_number(va)) snprintf(bd + strlen(bd), 1023, "<0x%X> ", PZ_ADR(va));
  }
  Id s = pz_to_string(b, va);
  snprintf(bd + strlen(bd), PZ_CELL_SIZE, "%s", pz_string_ptr(s));
  return S(bd);
}

Id __d(void *b, const char *where, int l, const char *comment, Id va) {
  printf("%lx [%s:%d] %s\n", (size_t)b, where, l, pz_string_ptr(__ds(b, comment, va))); 
  return va; 
}

