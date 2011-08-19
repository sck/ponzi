
#define D(c, va) __d(b, __FUNCTION__, __LINE__, c, va)


Id __d(void *b, const char *where, int l, const char *comment, Id va) {
  if (!debug) return va;
  printf("%lx [%s:%d] %s ", (size_t)b, where, l, comment);
  pz_print_dump(b, va, PZ_DUMP_INSPECT | PZ_DUMP_RECURSE);
  //pz_print_dump(b, va, PZ_DUMP_DEBUG);
  printf("\n");
  return va; 
}

