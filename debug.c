
Id cl_debug() { 
}
#define D(c, va) __d(__FUNCTION__, __LINE__, c, va);

Id cl_to_string(void *b, Id exp);
char *cl_string_ptr(void *b, Id va_s);

// DEBUG
Id __ds(void *b, const char *comment, Id va) {
  char bd[CL_CELL_SIZE * 2];
  snprintf(bd, 1023, "%s%s%s", comment, strlen(comment) > 0 ? " " : "", 
      cl_type_to_i_cp(CL_TYPE(va)));
  if (!cl_is_string(va) && CL_TYPE(va) != CL_TYPE_ARRAY)  {
    snprintf(bd + strlen(bd), 1023, "%s:", cl_type_to_cp(CL_TYPE(va)));
    if (!cl_is_number(va)) snprintf(bd + strlen(bd), 1023, "<0x%X> ", CL_ADR(va));
  }
  Id s = cl_to_string(b, va);
  snprintf(bd + strlen(bd), CL_CELL_SIZE, "%s%s", cl_string_ptr(b, s), 
      CL_TYPE(va) == CL_TYPE_STRING ? "'" : "");
  return S(bd);
}

Id __d(void *b, const char *where, int l, const char *comment, Id va) {
  printf("[%s:%d] %s\n", where, l, cl_string_ptr(b, __ds(b, comment, va))); 
  return va; 
}

