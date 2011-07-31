/*
 * Copyright (c) 2010, 2011, Sven C. Koehler
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/time.h>

#include "atomic.c"

#define CL_VERSION "0.0.1"
#define CL_GC_DEBUG 

typedef union {
  float f;
  int i;
  int address;
} cl_reg_type;

typedef union {
  size_t s;
  struct {
    short int type;
    cl_reg_type d;
  } t;
} Id;


#define CL_DB_MAGIC 0xF0F0
#define CL_DB_VERSION 1

#define CL_ADR(va) va.t.d.address
#define CL_TYPE(va) va.t.type
#define CL_INT(va) va.t.d.i
#define CL_FLOAT(va) va.t.d.f

static Id clNil = {0}; 
static Id clTrue = {0}; // This is set to 1 later
static Id clTail = {0}; // set to 2 later

/*
 * Basic error handling
 */

typedef struct {
  char error_str[1024];
  int error_number;
} cl_error_t;

cl_error_t cl_error;
int cl_interactive = 1, cl_verbose = 1;
FILE *fin;

void cl_reset_errors() { memset(&cl_error, 0, sizeof(cl_error)); }
int cl_have_error() { return cl_error.error_str[0] != 0x0; }
#define CE(w) if (cl_have_error()) { printf("errors\n"); w; }
Id cl_handle_error_with_err_string(const char *ctx, 
    const char *error_msg, char *handle) {
  char h[1024];
  if (handle != 0)  { snprintf(h, 1023, " '%s'", handle); } 
  else { strcpy(h, ""); }
  snprintf((char *)&cl_error.error_str, 1023, "%s%s: %s", ctx, h, error_msg);
  printf("error: %s\n", cl_error.error_str);
  cl_error.error_number = errno;
  return clNil;
}

Id cl_handle_error(int check, const char *ctx, char *handle) {
  if (!check) { return clTrue; } 
  return cl_handle_error_with_err_string(ctx, strerror(errno), handle);
}

Id cl_handle_error_with_err_string_nh(const char *ctx, 
    const char *error_msg) { 
  return cl_handle_error_with_err_string(ctx, error_msg, 0);
}

/* 
 * Memory primitives 
 */

#define CL_STATIC_ALLOC_SIZE 65536
#define CL_VAR_COUNT 100000LL
#define CL_MEM_SIZE (size_t)(CL_VAR_COUNT * CL_STATIC_ALLOC_SIZE)
#define CL_PERF_MEM_SIZE (size_t)(200LL * CL_STATIC_ALLOC_SIZE)

#ifdef CL_GC_DEBUG
typedef struct {
  const char *where;
  int line;
  int new;
  const char *retain_where;
  int retain_line;
  int retain_adr;
  size_t release_counter;
  size_t retain_counter;
} cl_var_status_t;

cl_var_status_t cl_var_status[CL_VAR_COUNT];

void cl_register_var(Id va, const char *where, int line) {
  int adr = CL_ADR(va);
  cl_var_status[adr].where = where;
  cl_var_status[adr].line = line;
  cl_var_status[adr].new = 1;
}
#else
#define cl_register_var(va, where, line)
#endif

void *cl_private_memory_create() {
  void *base = 0;
  base = mmap(0, CL_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 
      -1, (off_t)0);
  if (!cl_handle_error(base == MAP_FAILED, "mmap", 0).s) return 0;
  return base;
}

typedef struct {
  int fd;
  void *base;
  char *filename;
  size_t size;
} cl_shm_t;

cl_shm_t *cl_perf_mc;

int cl_does_filename_exist(char *fn) {
  struct stat st;
  return stat(fn, &st) != -1;
}

void cl_ensure_filename(char *fn) {
  if (!cl_does_filename_exist(fn)) close(open(fn, O_CREAT, 0777)); 
}

cl_shm_t *cl_shared_memory_create(char *fn, size_t size) {
  cl_ensure_filename(fn);  
  cl_shm_t *mc = calloc(1, sizeof(cl_shm_t));
  if (!mc) {
    cl_handle_error_with_err_string_nh( __FUNCTION__, "Out of memory");
    return 0;
  }

  mc->filename = fn;
  mc->size = size;
  void *base = 0;
  if (!cl_handle_error((mc->fd = open(fn, O_RDWR, (mode_t)0777)) == -1, 
      "open", fn).s) goto open_failed;
  if (!cl_handle_error(lseek(mc->fd, mc->size - 1, SEEK_SET) == -1, 
      "lseek", fn).s) goto failed;
  if (!cl_handle_error(write(mc->fd, "", 1) != 1, "write", fn).s) goto failed;
  mc->base = mmap(0, mc->size, PROT_READ | PROT_WRITE, MAP_SHARED, mc->fd, 
      (off_t)0);
  if (!cl_handle_error(mc->base == MAP_FAILED, "mmap", fn).s) goto failed;

  return mc;

failed:
  close(mc->fd);
open_failed:
  free(mc);
  return 0;
}

/* 
 * Memory management
 */

// for garbage collection
#define RCS (sizeof(int)+sizeof(short int))
#define rc_t int
#define CL_CELL_SIZE (CL_STATIC_ALLOC_SIZE - RCS)

#ifdef sizeof(size_t) != 8
#error sizeof(size_t) must be 8 bytes!!
#endif

#define CL_TYPE_BOOL 0
#define CL_TYPE_FLOAT 1
#define CL_TYPE_INT 2
#define CL_TYPE_SPECIAL 3

#define cl_string_size_t short int

typedef struct {
  int rc_dummy;  
  Id first_free;
  size_t heap_size;
  size_t total_size;
  int magic;
  int version;
  Id symbols;
  Id globals;
} cl_mem_descriptor_t;

typedef struct {
  int rc_dummy; 
  Id next;
  size_t size;
} cl_mem_chunk_descriptor_t;

size_t cl_header_size() { return CL_STATIC_ALLOC_SIZE * 3; }
Id cl_header_size_ssa() { Id a; CL_ADR(a) = 3; return a; }
#define cl_md __cl_md(b)
void *cl_heap = 0;
void *cl_perf = 0;

cl_mem_descriptor_t *__cl_md(void *b) { return b; }


#define VA_TO_PTR0(va) \
  ((va).s ? b + RCS + ((size_t)CL_ADR(va) * CL_STATIC_ALLOC_SIZE) : 0) 
#define PTR_TO_VA(va, p) \
  CL_ADR(va) = (int)(((p) - RCS - (char *)b) / CL_STATIC_ALLOC_SIZE);

#define P_0_R(p, r) if (!(p)) { printf("From %s:%d\n", __FUNCTION__, __LINE__); return (r); }
#define P_0_R2(w, l, p, r) if (!(p)) { printf("From %s:%d\n", w, l); return (r); }
#define VA_0_R(va, r) if (!(va).s) { return (r); }
#define VA_TO_PTR(va) (__ca(b, va, __FUNCTION__, __LINE__) ? VA_TO_PTR0(va) : 0 )

int __ca(void *b, Id va, const char *where, int line) {
  char *p0 = VA_TO_PTR0(va); P_0_R(p0, 1); 
  rc_t *rc = (rc_t *)(p0 - RCS);
  if ((*rc) == 0) { printf("[%s:%d] error: VA is not allocated!\n", where, line); abort(); }
  //if ((*rc) == 1) { printf("[%s:%d] Warning: RC is 0\n", where, line); abort(); }
  return 1;
}

int cnil(Id i) { return i.s == clNil.s; }
Id cb(int i) { return i ? clTrue : clNil; }

cl_mem_chunk_descriptor_t *cl_md_first_free(void *b) {
    return VA_TO_PTR0(cl_md->first_free);}


int cl_var_free(void *b) {
    return (cl_md->total_size - cl_md->heap_size) / CL_STATIC_ALLOC_SIZE; }
  

#define CL_TYPE_STRING 4
#define CL_TYPE_SYMBOL 5
#define CL_TYPE_CFUNC 6
#define CL_TYPE_HASH 7
#define CL_TYPE_HASH_PAIR 8
#define CL_TYPE_ARRAY 9
#define CL_TYPE_MAX 9

#ifdef CL_GC_DEBUG
Id __cl_retain(const char *where, int line, void *b, Id from, Id va);
#else
Id __cl_retain(void *b, Id va);
#endif
#define CL_HEAP_SIZE \
    ((CL_MEM_SIZE / CL_STATIC_ALLOC_SIZE) * CL_STATIC_ALLOC_SIZE)
int cl_init_memory(void *b, size_t size) {
  size_t s = size - cl_header_size();
  if (cl_md->magic != CL_DB_MAGIC) {
    cl_md->first_free = cl_header_size_ssa();
    cl_md->total_size = s;
    cl_mem_chunk_descriptor_t *c = cl_md_first_free(b);
    c->next.s = 0;
    c->size = s;

    CL_ADR(cl_md->symbols) = 1;
    CL_TYPE(cl_md->symbols) = CL_TYPE_HASH; 
#ifdef CL_GC_DEBUG
    __cl_retain(__FUNCTION__, __LINE__, b, clNil, cl_md->symbols);
#else
    __cl_retain(b, cl_md->symbols);
#endif

    CL_ADR(cl_md->globals) = 2;
    CL_TYPE(cl_md->globals) = CL_TYPE_HASH; 
#ifdef CL_GC_DEBUG
    __cl_retain(__FUNCTION__, __LINE__, b, clNil, cl_md->globals);
#else
    __cl_retain(b, cl_md->globals);
#endif

    cl_md->magic = CL_DB_MAGIC;
    cl_md->version = CL_DB_VERSION;
    return 1;
  } else if (cl_md->version != CL_DB_VERSION) {
    char es[1024]; 
    snprintf(es, 1023, "DB version is %d.  Current version is %d.", 
        cl_md->version, CL_DB_VERSION);  
    cl_handle_error_with_err_string_nh(__FUNCTION__, es);
    return 2;
  }
  return 0;
}

char *cl_type_to_cp(short int t);

int cl_perf_mode = 0;

void cl_alloc_debug(void *b, char *p, short int type) {
  if (!cl_perf_mode || b != cl_perf) return;
  char *n = b == cl_perf ? "perf" : "scheme";
  printf("[%s:%lx] alloc %lx type: %s\n", n, (size_t)b, (size_t)p, 
      cl_type_to_cp(type));
}

Id cl_valloc(void *b, const char *where, short int type) {
  cl_mem_chunk_descriptor_t *c = cl_md_first_free(b); 
  if (!c) return cl_handle_error_with_err_string_nh(where, "1: Out of memory");
  Id r = { 0x0 };
  if (c->size < CL_STATIC_ALLOC_SIZE)
      return cl_handle_error_with_err_string_nh(where, "2: Out of memory");
  if (c->size == CL_STATIC_ALLOC_SIZE) {
    // chunk size ==  wanted size
    cl_md->first_free = c->next; 
    PTR_TO_VA(r, (char *)c);
  } else {
    // chunk is larger than wanted 
    c->size -= CL_STATIC_ALLOC_SIZE;
    PTR_TO_VA(r, (char *)c + c->size);
  }
  if (!c->next.s) { cl_md->heap_size += CL_STATIC_ALLOC_SIZE; }
  if (r.s) { 
    CL_TYPE(r) = type; 
    char *p = VA_TO_PTR0(r);
    rc_t *rc = (rc_t *) (p - RCS);
    *rc = 0x1;
    cl_alloc_debug(b, (char *)rc, type);
    short int *t = (short int *)(p - sizeof(short int));
    *t = type;
  }
  return r; 
}

int cl_zero(void *b, Id va) { 
  char *p = VA_TO_PTR0(va); P_0_R(p, 0); 
  memset(p, 0, CL_CELL_SIZE); return 0;}

#define CL_ALLOC(va, type) va = cl_valloc(b, __FUNCTION__, type); VA_0_R(va, clNil);

int cl_free(void *b, Id va) {
  int t = CL_TYPE(va);
  if (t == CL_TYPE_BOOL || t == CL_TYPE_FLOAT || t == CL_TYPE_INT) return 0;
  char *used_chunk_p = VA_TO_PTR(va); P_0_R(used_chunk_p, 0);
  cl_mem_chunk_descriptor_t *mcd_used_chunk = 
      (cl_mem_chunk_descriptor_t *)used_chunk_p;
  mcd_used_chunk->next = cl_md->first_free;
  mcd_used_chunk->size = CL_STATIC_ALLOC_SIZE;
  mcd_used_chunk->rc_dummy = 0;
  cl_md->first_free = va;
  return 1;
}

/*
 * Register types.
 */

Id cl_int(int i) { 
    Id va; CL_TYPE(va) = CL_TYPE_INT; CL_INT(va) = i; return va; }

Id cl_float(float f) { 
    Id va; CL_TYPE(va) = CL_TYPE_FLOAT; CL_FLOAT(va) = f; return va; }

Id cn(Id v) { return CL_TYPE(v) == CL_TYPE_BOOL ? cl_int(v.s ? 1 : 0) : v; }

/*
 * Basic types 
 */


char *cl_types_s[] = {"nil", "float", "int", "special", "string", "symbol", "cfunc", "hash", 
    "hash pair", "array"};
char *cl_types_i[] = {"x", "f", "i", "S", "s", ":", "C", "{", "P", "["};

char *cl_type_to_cp(short int t) {
  if (t > CL_TYPE_MAX || t < 0) { return "<unknown>"; }
  return cl_types_s[t];
}

char *cl_type_to_i_cp(short int t) {
  if (t > CL_TYPE_MAX || t < 0) { return "?"; }
  return cl_types_i[t];
}

int cl_is_string(Id va) { 
    return CL_TYPE(va) == CL_TYPE_SYMBOL || CL_TYPE(va) == CL_TYPE_STRING; }
int cl_is_number(Id va) { 
    return CL_TYPE(va) == CL_TYPE_FLOAT || CL_TYPE(va) == CL_TYPE_INT; }
int c_type(int t) { return t == CL_TYPE_SYMBOL ? CL_TYPE_STRING : t;}
int cl_is_type_i(Id va, int t) { return c_type(CL_TYPE(va)) == c_type(t); }
#define S(s) cl_string_new_c(b, s)


#define CL_CHECK_TYPE(va, _type, r) \
  if (!cl_is_type_i((va), (_type))) { \
    char es[1024]; \
    snprintf(es, 1023, "Invalid type: Expected type '%s', have: '%s'", \
        cl_type_to_cp((_type)), cl_type_to_cp(CL_TYPE(va)));  \
    cl_handle_error_with_err_string_nh(__FUNCTION__, es); \
    return (r); \
  }

#define CL_CHECK_ERROR(cond,msg,r) \
  if ((cond)) { cl_handle_error_with_err_string_nh(__FUNCTION__, (msg)); return (r); }

#define __CL_TYPED_VA_TO_PTR(ptr, va, type, r, check) \
  CL_CHECK_TYPE((va), (type), (r)); (ptr) = check((va)); P_0_R((ptr), (r));
#define CL_TYPED_VA_TO_PTR(p,v,t,r) __CL_TYPED_VA_TO_PTR(p,v,t,r,VA_TO_PTR)
#define CL_TYPED_VA_TO_PTR0(p,v,t,r) __CL_TYPED_VA_TO_PTR(p,v,t,r,VA_TO_PTR0)

/*
 * Reference counting.
 */

#define RCI if (!va.s || va.t.type < 3) { return va; }; char *p0 = VA_TO_PTR0(va); \
  P_0_R(p0, clNil); rc_t *rc = (rc_t *)(p0 - RCS);

int cl_ary_free(void *b, Id);
int cl_ht_free(void *b, Id);

#define cl_release(va) __cl_release(b, va)
Id __cl_release(void *b, Id va) { 
  RCI; CL_CHECK_ERROR((*rc <= 1), "Reference counter is already 0!", clNil);
#ifdef CL_GC_DEBUG
  cl_var_status[CL_ADR(va)].release_counter++;
#endif
  --(*rc);
  return va;
}

Id cl_delete(void *b, Id va) { 
  RCI; 
  if ((*rc) == 0x0) return clNil; // ignore, so one can jump at random address!
  CL_CHECK_ERROR((*rc != 1), "Cannot delete, rc != 0!", clNil);
  switch (CL_TYPE(va)) {
    case CL_TYPE_ARRAY: cl_ary_free(b, va); break;
    case CL_TYPE_HASH: cl_ht_free(b, va); break;
    case CL_TYPE_HASH_PAIR: /* ignore: will always be freed by hash */; break;
    default: cl_free(b, va); break;
  }
  (*rc) = 0x0;
  return clTrue;
}

size_t __cl_mem_dump(void *b, int silent) {
  size_t entries = cl_md->heap_size / CL_STATIC_ALLOC_SIZE;
  size_t mem_start = cl_md->total_size + cl_header_size() - 
      cl_md->heap_size;
  if (!silent) printf("totalsize: %ld\n", cl_md->total_size);
  char *p = mem_start + b;
  size_t i;
  size_t active_entries = 0;
  if (!silent) printf("[%lx] mem dump: entries: %ld\n", (size_t)b, entries);
  for (i = 0; i < entries; ++i, p += CL_STATIC_ALLOC_SIZE) {
    rc_t *rc = (rc_t *)p;
    if (*rc > 0) {
      active_entries++;
      short int *t = (short int *) (p + sizeof(int));
      Id r;
      PTR_TO_VA(r, (char *)p + RCS);
#ifdef CL_GC_DEBUG
      cl_var_status_t *s = &cl_var_status[CL_ADR(r)];
      if (!silent) {
        //printf("%s%x:%d%s ", cl_var_status[CL_ADR(r)].new ? "NEW" : "",
        //CL_ADR(r), *rc, cl_type_to_i_cp(*t));
        if (s->new) {
          printf("NEW: %x %d %s:%d %s retain from %s:%d %x %ld:%ld\n", 
              CL_ADR(r), 
              *rc, s->where, s->line, cl_type_to_cp(*t), s->retain_where,
              s->retain_line, s->retain_adr, s->retain_counter, 
              s->release_counter);
        }
      }
      cl_var_status[CL_ADR(r)].new = 0;
#endif
    }
  }
  //if (!silent) printf("active: %ld\n", active_entries);
  return active_entries;
}

size_t cl_mem_dump(void *b) { return __cl_mem_dump(b, 0); }
size_t cl_active_entries(void *b) { return __cl_mem_dump(b, 1); }

size_t cl_max(size_t a, size_t b) { return a > b ? a : b; }
size_t cl_min(size_t a, size_t b) { return a < b ? a : b; }

void cl_garbage_collect(void *b) {
  size_t entries = cl_md->heap_size / CL_STATIC_ALLOC_SIZE;
  if ((rand() & 1023) != 0) entries = cl_min(entries, 10);
  size_t mem_start = cl_md->total_size + cl_header_size() - 
      cl_md->heap_size;
  char *p = mem_start + b;
  size_t i;
  //printf("GC: ");
  for (i = 0; i < entries; ++i, p += CL_STATIC_ALLOC_SIZE) {
    rc_t *rc = (rc_t *)p;
    short int *t = (short int *) (p + sizeof(int));
    if (*rc == 1) {
      Id va;
      PTR_TO_VA(va, p + RCS);
      CL_TYPE(va) = *t;
      //printf("%x%s ", CL_ADR(va), cl_type_to_i_cp(*t));
      cl_delete(b, va);
    }
  }
  //printf("\n");
}

#ifdef CL_GC_DEBUG
#define cl_retain(from, va) __cl_retain(__FUNCTION__, __LINE__, b, from, va)
#define cl_retain2(from, va) __cl_retain(where, line, b, from, va)
Id __cl_retain(const char *where, int line, void *b, Id va_from, Id va) { 
#else
#define cl_retain(from, va) __cl_retain(b, va)
#define cl_retain2(from, va) __cl_retain(b, va)
Id __cl_retain(void *b, Id va) { 
#endif

  RCI;
#ifdef CL_GC_DEBUG
  cl_var_status[CL_ADR(va)].retain_where = where;
  cl_var_status[CL_ADR(va)].retain_line = line;
  cl_var_status[CL_ADR(va)].retain_adr = CL_ADR(va_from);
  cl_var_status[CL_ADR(va)].retain_counter++;
#endif
  (*rc)++; return va; }

/*
 * String
 */

#define CL_STR_MAX_LEN (CL_CELL_SIZE - sizeof(cl_string_size_t))

int cl_strdup(void *b, Id va_dest, char *source, cl_string_size_t l) {
  char *p; CL_TYPED_VA_TO_PTR0(p, va_dest, CL_TYPE_STRING, 0);
  CL_CHECK_ERROR((l + 1 > CL_STR_MAX_LEN), "strdup: string too large", 0);
  *(cl_string_size_t *) p = l;
  p += sizeof(cl_string_size_t);
  memcpy(p, source, l);
  p += l;
  (*p) = 0x0;
  return 1;
}

Id cl_string_new(void *b, char *source, cl_string_size_t l) { 
  Id va; CL_ALLOC(va, CL_TYPE_STRING);
  if (l > 0 && !cl_strdup(b, va, source, l)) return clNil;
  return va;
}

Id cl_string_new_c(void *b, char *source) { 
    return cl_string_new(b, source, strlen(source)); }
#define cl_string_ptr(s) __cl_string_ptr(__FUNCTION__, __LINE__, b, s)
char *__cl_string_ptr(const char *w, int l, void *b, Id va_s);

#include "debug.c"

Id __cl_snn(void *b, Id n, const char *f) { 
  Id va; CL_ALLOC(va, CL_TYPE_STRING);
  int i = CL_TYPE(n) == CL_TYPE_INT;
  char ns[1024]; 
  i ? snprintf(ns, 1023, f, CL_INT(n)) : 
      snprintf(ns, 1023, "%f", CL_FLOAT(n));
  return S(ns);
}

Id cl_string_new_number(void *b, Id n) { return __cl_snn(b, n, "%d"); }
Id cl_string_new_hex_number(void *b, Id n) { return __cl_snn(b, n, "0x%x"); }

typedef struct { char *s; cl_string_size_t l; } cl_str_d;
int sr = 0;
#define CL_ACQUIRE_STR_D(n,va,r) \
  cl_str_d n; sr = cl_acquire_string_data(b, va, &n); P_0_R(sr, r);
#define CL_ACQUIRE_STR_D2(n,va,r) \
  cl_str_d n; sr = cl_acquire_string_data(b, va, &n); P_0_R2(w, l, sr, r);

Id cl_string_sub_str_new(void *b, Id s, int start, int _count) {
  CL_ACQUIRE_STR_D(dt, s, clNil);
  if (start > dt.l) start = dt.l;
  int count = (_count < 0) ? (dt.l + _count + 1) - start : _count;
  if (count < 0) count = 0;
  if (count > dt.l - start) count = dt.l - start;
  char sym[dt.l + 1];
  memcpy(&sym, dt.s + start, count);
  return cl_string_new(b, (char *)&sym, count);
}

Id cl_string_new_0(void *b) { return cl_string_new(b, "", 0); }

int cl_acquire_string_data(void *b, Id va_s, cl_str_d *d) { 
  char *s; CL_TYPED_VA_TO_PTR(s, va_s, CL_TYPE_STRING, 0);
  d->s = s + sizeof(cl_string_size_t); d->l = *(cl_string_size_t *) s; 
  return 1;
}

char *__cl_string_ptr(const char *w, int l, void *b, Id va_s) { 
    if (cnil(va_s)) return 0;
    CL_ACQUIRE_STR_D2(ds, va_s, 0x0); return ds.s; }

Id cl_string_append(void *b, Id va_d, Id va_s) {
  CL_ACQUIRE_STR_D(dd, va_d, clNil); CL_ACQUIRE_STR_D(ds, va_s, clNil);
  size_t l = dd.l + ds.l;
  CL_CHECK_ERROR((l + 1 > CL_STR_MAX_LEN), "append: string too large", clNil);
  memcpy(dd.s + dd.l, ds.s, ds.l);
  *(cl_string_size_t *) (dd.s - sizeof(cl_string_size_t)) = l;
  dd.s += l;
  (*dd.s) = 0x0;
  return va_d;
}

int cl_string_hash(void *b, Id va_s, size_t *hash) {
  CL_ACQUIRE_STR_D(ds, va_s, 0); char *s = ds.s;
  size_t v;
  cl_string_size_t i;
  for (v = 0, i = 0; i++ < ds.l; s++) { v = *s + 31 * v; }
  (*hash) = v;
  return 1;
}

#define cl_string_equals_cp_i(s, sb)  \
    __cl_string_equals_cp_i(__FUNCTION__, __LINE__, b, s, sb)
int __cl_string_equals_cp_i(const char *w, int l, void *b, Id va_s, char *sb) {
  CL_ACQUIRE_STR_D2(ds, va_s, 0); 
  size_t bl = strlen(sb);
  if (ds.l != bl) { return 0; }
  cl_string_size_t i;
  for (i = 0; i < ds.l; i++) { if (ds.s[i] != sb[i]) return 0; }
  return 1;
}

void __cp(char **d, char **s, size_t l, int is) {
    memcpy(*d, *s, l); (*d) += l; if (is) (*s) += l; }

int cl_string_starts_with(void *b, Id va_s, Id va_q) {
  CL_ACQUIRE_STR_D(ds, va_s, 0); CL_ACQUIRE_STR_D(dq, va_q, 0); 
  if (dq.l > ds.l) return 0;
  return strncmp(ds.s, dq.s, dq.l) == 0;
}

Id cl_string_replace(void *b, Id va_s, Id va_a, Id va_b) {
  CL_ACQUIRE_STR_D(ds, va_s, clNil); CL_ACQUIRE_STR_D(da, va_a, clNil); 
  CL_ACQUIRE_STR_D(db, va_b, clNil); 
  Id va_new = cl_string_new_0(b); CL_ACQUIRE_STR_D(dn, va_new, clNil);
  char *dp = dn.s, *sp = ds.s; P_0_R(dp, clNil)
  size_t i, match_pos = 0;
  for (i = 0; i < ds.l; i++) {
    if (ds.s[i] != da.s[match_pos]) {
      match_pos = 0;
      continue;
    }
    if (match_pos == da.l - 1) {
      size_t l = i - (sp - ds.s) - match_pos;
      __cp(&dp, &sp, l, 1);
      sp += da.l;
      __cp(&dp, &db.s, db.l, 0);
      match_pos = 0;
      continue;
    }
    match_pos++;
  }
  __cp(&dp, &sp, (size_t)ds.l - (sp - ds.s), 0);
  *(cl_string_size_t *)(dn.s - sizeof(cl_string_size_t)) = dp - dn.s;
  return va_new;
}

/*
 * general var handling
 */

size_t cl_hash_var(void *b, Id va) {
  if (CL_TYPE(va) == CL_TYPE_STRING) {
    size_t h;
    cl_string_hash(b, va, &h);
    return h;
  }
  return va.s;
}

Id cnil2(Id i) { 
    return CL_TYPE(i) == CL_TYPE_ARRAY && cl_ary_len(i) == 0 ? clNil : i; }

#define cl_equals_i(a, o) __cl_equals_i(b, a, o)
int __cl_equals_i(void *b, Id a, Id o) {
  if (CL_TYPE(a) == CL_TYPE_STRING && CL_TYPE(o) == CL_TYPE_STRING) {
     CL_ACQUIRE_STR_D(da, a, 0); CL_ACQUIRE_STR_D(db, o, 0); 
     if (da.l != db.l) return 0;
     cl_string_size_t i;
     for (i = 0; i < da.l; i++) {
        if (da.s[i] != db.s[i]) return 0; }
     return 1;
  } 
  return cnil2(a).s == cnil2(o).s;
}


/*
 * Hashtable
 */

typedef struct {
  Id va_key;
  Id va_value;
  Id va_next;
} cl_ht_entry_t;
#define CL_HT_BUCKETS ((CL_CELL_SIZE - (2 * sizeof(Id))) / sizeof(Id))
typedef struct {
  int size;
  Id va_buckets[CL_HT_BUCKETS];
  Id va_parent;
} cl_hash_t;

Id cl_ht_new(void *b) {
    Id va_ht; CL_ALLOC(va_ht, CL_TYPE_HASH); cl_zero(b, va_ht); return va_ht; }

size_t cl_ht_hash(void *b, Id va_s) {
    return cl_hash_var(b, va_s) % CL_HT_BUCKETS; }

cl_ht_entry_t cl_ht_null_node = { 0, 0, 0 };

#define CL_HT_ITER_BEGIN(r) \
  Id va_hr; cl_ht_entry_t *hr = &cl_ht_null_node; \
  cl_hash_t *ht; CL_TYPED_VA_TO_PTR(ht, va_ht, CL_TYPE_HASH, (r)); \
  size_t k = cl_ht_hash(b, va_key); \
  for (va_hr = ht->va_buckets[k];  \
      va_hr.s != 0 && hr != NULL; ) { \
    CL_TYPED_VA_TO_PTR(hr, va_hr, CL_TYPE_HASH_PAIR, (r)); \
    if (!hr || !cl_equals_i(va_key, hr->va_key)) goto next; 

#define CL_HT_ITER_END(v) } return (v);

int cl_ht_lookup(void *b, cl_ht_entry_t **_hr, Id va_ht, Id va_key) {
  (*_hr) = &cl_ht_null_node; 
  CL_HT_ITER_BEGIN(0) 
    (*_hr) = hr;
    return 1;
    next: va_hr = hr->va_next;
  CL_HT_ITER_END(0);
}

Id cl_ht_delete(void *b, Id va_ht, Id va_key) {
  Id va_p = clNil;
  CL_HT_ITER_BEGIN(clNil);
    cl_ht_entry_t *p = VA_TO_PTR(va_p);
    if (p) { p->va_next = hr->va_next; }
    else { ht->va_buckets[k] = clNil; }
    cl_release(hr->va_value); cl_release(hr->va_key); cl_free(b, va_hr);
    ht->size -= 1;
    return clTrue; 
  next: va_p = va_hr;
  CL_HT_ITER_END(clTrue);
}

int cl_ht_free(void *b, Id va_ht) {
  int k; Id va_hr, va_p = clNil; cl_ht_entry_t *hr = &cl_ht_null_node; 
  cl_hash_t *ht; CL_TYPED_VA_TO_PTR(ht, va_ht, CL_TYPE_HASH, 0); 
  for (k = 0; k < CL_HT_BUCKETS; k++) {
    for (va_hr = ht->va_buckets[k]; va_hr.s != 0 && hr != NULL; va_hr = hr->va_next) {
      CL_TYPED_VA_TO_PTR(hr, va_hr, CL_TYPE_HASH_PAIR, 0); 
      cl_release(hr->va_value); cl_release(hr->va_key); 
      if (va_p.s) { cl_release(va_p); cl_free(b, va_p); }
      va_p = va_hr;
    }
  }
  if (va_p.s) { cl_release(va_p); cl_free(b, va_p); }
  cl_free(b, va_ht);
  return 1;
}

#define cl_ary_new(b) __cl_ary_new(__FUNCTION__, __LINE__, b)
Id __cl_ary_new(const char *where, int line, void *b);
#define cl_ary_push(b, var_ary, va) \
  __cl_ary_push(__FUNCTION__, __LINE__, b, var_ary, va)
Id __cl_ary_push(const char *where, int line, void *b, Id va_ary, Id va);

Id cl_ht_map(void *b, Id va_ht, Id (*func_ptr)(void *b, Id)) {
  int k; Id va_hr; cl_ht_entry_t *hr = &cl_ht_null_node; 
  cl_hash_t *ht; CL_TYPED_VA_TO_PTR(ht, va_ht, CL_TYPE_HASH, clNil); 
  Id r = cl_ary_new(b);
  for (k = 0; k < CL_HT_BUCKETS; k++) {
    for (va_hr = ht->va_buckets[k]; va_hr.s != 0 && hr != NULL; va_hr = hr->va_next) {
      Id s = cl_string_new_0(b);
      CL_TYPED_VA_TO_PTR(hr, va_hr, CL_TYPE_HASH_PAIR, clNil); 
      cl_string_append(b, s, func_ptr(b, hr->va_key));
      cl_string_append(b, s, S(" => "));
      cl_string_append(b, s, func_ptr(b, hr->va_value));
      cl_ary_push(b, r, s);
    }
  }
  return r;
}

Id cl_ht_get(void *b, Id va_ht, Id va_key) { 
  cl_ht_entry_t *hr; cl_ht_lookup(b, &hr, va_ht, va_key);  P_0_R(hr, clNil);
  return hr->va_value;
}

#define cl_ht_set(b, va_ht, va_key, va_value) \
  __cl_ht_set(__FUNCTION__, __LINE__, b, va_ht, va_key, va_value)
Id __cl_ht_set(const char *where, int line, void *b, Id va_ht, Id va_key, 
    Id va_value) {
//set_new_entry_failed:
  cl_hash_t *ht; CL_TYPED_VA_TO_PTR(ht, va_ht, CL_TYPE_HASH, clNil);
  cl_ht_entry_t *hr; cl_ht_lookup(b, &hr, va_ht, va_key);
  size_t v;
  int new_entry = !hr->va_value.s;
  Id va_hr;
  if (new_entry) { 
    v = cl_ht_hash(b, va_key);
    CL_ALLOC(va_hr, CL_TYPE_HASH_PAIR);
    cl_register_var(va_hr, where, line);
    cl_retain2(va_ht, va_hr); hr = VA_TO_PTR(va_hr); P_0_R(hr, clNil);
    // cl_atomic_cas
    // if it fails: go back where?
    //   -> before new entry: set_new_entry_failed
    //   -> release key!
    hr->va_key = cl_retain2(va_hr, va_key);
    // XXX cl_atomic_inc
    ht->size += 1;
  } else {
    // XXX we may release multiple times with CAS...
    // value_released = 1
    cl_release(hr->va_value);
  }

  // XXX cl_atomic_cas!
  // if it fails: retain is not valid anymore...
  //  better retain before going here..
  hr->va_value = cl_retain2(va_hr, va_value);

  if (new_entry) {
    // XXX cl_atomic_cas!
    hr->va_next = ht->va_buckets[v];
    // XXX cl_atomic_cas!
    // what if this fails and the previous succeeds?
    ht->va_buckets[v] = va_hr;
  }
  return va_value;
}

Id cl_ht_inc(void *b, Id va_ht, Id va_key) {
  Id v = cl_ht_get(b, va_ht, va_key);
  if (cnil(v)) v = cl_int(0);
  if (!cl_is_number(v)) return clNil;
  Id vn = cl_int(CL_INT(v) + 1);
  return cl_ht_set(b, va_ht, va_key, cl_int(CL_INT(v) + 1));
}

//Id cl_symbols;
#define cl_symbols cl_md->symbols
#define cl_globals cl_md->globals

#define cl_intern(s) __cl_intern(b, s)
Id __cl_intern(void *b, Id va_s) { 
  if (CL_TYPE(va_s) == CL_TYPE_SYMBOL) CL_TYPE(va_s) = CL_TYPE_STRING;
  Id va = cl_ht_get(b, cl_symbols, va_s); 
  if (va.s) { return va; }
  Id va_sym = va_s; CL_TYPE(va_sym) = CL_TYPE_SYMBOL;
  if (cnil(cl_ht_set(b, cl_symbols, va_s, va_sym))) return clNil;
  return cl_ht_get(b, cl_symbols, va_s); 
}

Id cl_env_new(void *b, Id va_ht_parent) {
  Id va = cl_ht_new(b);
  cl_hash_t *ht; CL_TYPED_VA_TO_PTR(ht, va, CL_TYPE_HASH, clNil);
  ht->va_parent = va_ht_parent;
  return va;
}

#define CL_ENV_FIND \
  Id va0 = va_ht, found = clNil; \
  while (va_ht.s && !(found = cl_ht_get(b, va_ht, va_key)).s) { \
    cl_hash_t *ht; CL_TYPED_VA_TO_PTR(ht, va_ht, CL_TYPE_HASH, clNil); \
    va_ht = ht->va_parent; \
  }

Id cl_env_find(void *b, Id va_ht, Id va_key) { 
  CL_ENV_FIND; 
  return found; 
}

Id cl_env_find_and_set(void *b, Id va_ht, Id va_key, Id va_value) { 
  CL_ENV_FIND;
  if (found.s) { return cl_ht_set(b, va_ht, va_key, va_value); }
  else { return cl_ht_set(b, va0, va_key, va_value); }
}

void cl_add_globals(void *b, Id env);

void cl_setup() {
  clTrue.s = 1;
  CL_TYPE(clTail) = CL_TYPE_SPECIAL;
  CL_INT(clTail)  = 1;
}

char *cmd;

char *cl_cmd_display() { return cl_perf_mode ? "perf" : "schemejit"; }

void *cl_init(void *b, size_t size) {
#ifdef CL_GC_DEBUG
  memset(&cl_var_status, 0, sizeof(cl_var_status));
#endif
  if (!b) return 0;
  int r = cl_init_memory(b, size);
  if (r == 2) return 0;
  if (r) cl_add_globals(b, cl_globals);
  if (cl_interactive) 
      printf("%s %s started; %d vars available\n", cl_cmd_display(), 
          CL_VERSION, cl_var_free(b));
  return b;
}

/*
 * FFI
 */

typedef struct { Id (*func_ptr)(void *b, Id, Id); } cl_cfunc_t;

Id cl_define_func(void *b, char *name, Id (*p)(void *b, Id, Id), Id env) { 
  Id va_f; CL_ALLOC(va_f, CL_TYPE_CFUNC);
  cl_cfunc_t *cf; CL_TYPED_VA_TO_PTR0(cf, va_f, CL_TYPE_CFUNC, clNil);
  cf->func_ptr = p;
  cl_ht_set(b, env, cl_intern(S(name)), va_f);
  return clTrue;
}

Id cl_call(void *b, Id va_f, Id env, Id x) { 
  cl_cfunc_t *cf; CL_TYPED_VA_TO_PTR(cf, va_f, CL_TYPE_CFUNC, clNil);
  Id r = cf->func_ptr(b, env, x);
  return r;
}

/*
 * Array
 */

#define CL_ARY_MAX_ENTRIES ((CL_CELL_SIZE - sizeof(Id)) / sizeof(Id))
typedef struct {
  int size;
  int start; 
  int lambda;
  Id va_entries[CL_ARY_MAX_ENTRIES];
} ht_array_t;

Id __cl_ary_new(const char *where, int line, void *b) {
  Id va_ary; CL_ALLOC(va_ary, CL_TYPE_ARRAY); 
  cl_register_var(va_ary, where, line);
  cl_zero(b, va_ary); return va_ary; 
}

void __ary_retain_all(void *b, Id from, ht_array_t *a) {
  int i = 0; 
  for (i = a->start; i < a->size; i++) cl_retain(from, a->va_entries[i]);
}

Id cl_ary_clone(void *b, Id va_s) {
  ht_array_t *ary_s; CL_TYPED_VA_TO_PTR(ary_s, va_s, CL_TYPE_ARRAY, clNil);
  Id va_c; CL_ALLOC(va_c, CL_TYPE_ARRAY);
  char *p_c = VA_TO_PTR(va_c), *p_s = VA_TO_PTR(va_s);
  memcpy(p_c, p_s, CL_CELL_SIZE);
  __ary_retain_all(b, va_c, (ht_array_t *)p_c);
  return va_c;
}

int cl_ary_free(void *b, Id va_ary) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, 0);
  int i = 0;
  for (i = ary->start; i < ary->size; i++) cl_release(ary->va_entries[i]);
  cl_free(b, va_ary);
  return 1;
}

Id cl_ary_new_join(void *b, Id a, Id o) {
  ht_array_t *aa; CL_TYPED_VA_TO_PTR(aa, a, CL_TYPE_ARRAY, clNil);
  ht_array_t *ab; CL_TYPED_VA_TO_PTR(ab, o, CL_TYPE_ARRAY, clNil);
  Id n; CL_ALLOC(n, CL_TYPE_ARRAY);
  ht_array_t *an; CL_TYPED_VA_TO_PTR(an, n, CL_TYPE_ARRAY, clNil);
  int aas = aa->size - aa->start;
  an->size = aas + ab->size - ab->start;
  CL_CHECK_ERROR((an->size >= CL_ARY_MAX_ENTRIES), "array is full", clNil);
  memcpy(&an->va_entries, &aa->va_entries + aa->start, aas * sizeof(Id));
  memcpy(&an->va_entries[aas + 1], &ab->va_entries + ab->start, 
      (ab->size - ab->start) * sizeof(Id));
  __ary_retain_all(b, n, an);
  return n;
}

Id cl_ary_join_by_s(void *b, Id va_ary, Id va_js) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  CL_ACQUIRE_STR_D(djs, va_js, clNil);
  char rs[CL_CELL_SIZE];
  cl_string_size_t ts = 0;
  int i;
  for (i = ary->start; i < ary->size; i++) {
    Id va_s = ary->va_entries[i];
    CL_ACQUIRE_STR_D(ds, va_s, clNil);
    CL_CHECK_ERROR((ts + ds.l + djs.l >= CL_CELL_SIZE),"join: array too large",clNil);
    memcpy(rs + ts, ds.s, ds.l);
    ts += ds.l;
    memcpy(rs + ts, djs.s, djs.l);
    ts += djs.l;
  }
  Id va_n = cl_string_new(b, rs, ts ? ts - djs.l : ts);
  return va_n;
}

Id __cl_ary_push(const char *where, int line, void *b, Id va_ary, Id va) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  CL_CHECK_ERROR((ary->size >= CL_ARY_MAX_ENTRIES), "array is full", clNil);
  ary->size += 1;
  ary->va_entries[ary->start + ary->size - 1] = cl_retain2(va_ary, va);
  return va_ary;
}

int cl_ary_set_lambda(void *b, Id va_ary) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, 0);
  ary->lambda = 1;
  return 1;
}

int cl_ary_is_lambda(void *b, Id va_ary) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, 0);
  return ary->lambda;
}


Id cl_ary_map(void *b, Id va_ary, Id (*func_ptr)(void *b, Id)) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  int i;
  Id r = cl_ary_new(b);
  for (i = ary->start; i < ary->size; i++) 
      cl_ary_push(b, r, func_ptr(b, ary->va_entries[i]));
  return r;
}

Id cl_ary_unshift(void *b, Id va_ary) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  if (ary->size - ary->start <= 0) { return clNil; } 
  ary->start++;
  return cl_release(ary->va_entries[ary->start - 1]);
}

Id cl_ary_set(void *b, Id va_ary, int i, Id va) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  CL_CHECK_ERROR((ary->start + i >= CL_ARY_MAX_ENTRIES), 
      "array index too large", clNil);
  if (i - ary->start > ary->size) ary->size = i - ary->start;
  Id va_o = ary->va_entries[ary->start + i];
  if (va_o.s) cl_release(va_o);
  // XXX cl_atomic_cas
  ary->va_entries[ary->start + i] = va;
  return va;
}

Id cl_ary_pop(void *b, Id va_ary) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  if (ary->size - ary->start <= 0) { return clNil; } 
  ary->size--;
  return cl_release(ary->va_entries[ary->start + ary->size]);
}

int cl_ary_len(void *b, Id va_ary) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, -1);
  return ary->size - ary->start;
}

Id cl_ary_index(void *b, Id va_ary, int i) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  if (ary->size - ary->start <= i) { return clNil; } 
  return ary->va_entries[ary->start + i];
}

Id ca_i(void *b, Id va_ary, int i) { return cl_ary_index(b, va_ary, i); }
#define ca_f(ary) ca_i(b, ary, 0)
#define ca_s(ary) ca_i(b, ary, 1)
#define ca_th(ary) ca_i(b, ary, 2)
#define ca_fth(ary) ca_i(b, ary, 3)

Id cl_ary_iterate(void *b, Id va_ary, int *i) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  if (*i >= ary->size - ary->start) { return clNil; }
  return cl_ary_index(b, va_ary, (*i)++); 
}

int cl_ary_contains_only_type_i(void *b, Id a, int t) {
  int i = 0; Id va;
  while ((va = cl_ary_iterate(b, a, &i)).s)
      if (!cl_is_type_i(va, t))  return 0;
  return 1;
}

#define CL_PUSH_STRING { \
    int l = ds.s + i - last_start - match_pos; \
    if (l > 0) { \
      Id va_ns = cl_string_new(b, last_start, l); VA_0_R(va_ns, clNil); \
      if (!cl_ary_push(b, va_ary, va_ns).s) return clNil; }}

Id cl_string_split(void *b, Id va_s, char sep) {
  Id va_ary = cl_ary_new(b);
  CL_ACQUIRE_STR_D(ds, va_s, clNil);
  if (ds.l == 0) return clNil;
  size_t i, match_pos = 0;
  char *last_start = ds.s;

  for (i = 0; i < ds.l; i++) {
    if (ds.s[i] != sep) {
      if (match_pos > 0) {
        CL_PUSH_STRING;
        last_start = ds.s + i;
        match_pos = 0;
      }
      continue;
    }
    match_pos++;
  }
  CL_PUSH_STRING;
  return va_ary;
}

Id cl_string_split2(void *b, Id va_s, Id sep) {
  CL_ACQUIRE_STR_D(ds, sep, clNil);
  if (ds.l == 0) return clNil;
  return cl_string_split(b, va_s, ds.s[0]);
}

Id cl_input(void *b, FILE *f, int interactive, char *prompt) {
  if (interactive) printf("%ld:%s", cl_active_entries(b), prompt); 
  Id cs = S("(begin");
  size_t l; 
  char *p;
next_line:
  p = fgetln(f, &l);
  if (l > 0 && (p[0] == ';' || p[0] == '#')) {
    if (interactive) return clNil;
    else goto next_line;
  }
  if (l > 0 && p[l - 1] == '\n') --l;
  Id s = cl_string_new(b, p, l);
  if (!interactive) {
    if (feof(f)) { 
      cl_string_append(b, cs, S(")"));
      return cs;
    }
    cl_string_append(b, cs, s);
    goto next_line;
  }
  //if (cl_verbose) printf("%s\n", cl_string_ptr(s));
  return s;
}

unsigned long cl_current_time_ms() {
  struct timeval now; 
  gettimeofday(&now, NULL); 
  return now.tv_sec * 1000 + (now.tv_usec / 1000);
}

#include "scheme-parser.c"

void test_atomic() {
  size_t s = 1;
  size_t n;
  size_t o, rr;
  rr = cl_atomic_cas(&s, 2, 1);
  printf("s: %ld r %ld\n", s, rr);
  rr = cl_atomic_add(&s, 10);
  printf("s: %ld r %ld\n", s, rr);
  rr = cl_atomic_inc(&s);
  printf("s: %ld r %ld\n", s, rr);

  exit(0);
}


int main(int argc, char **argv) {
  cl_setup();
  cl_interactive = isatty(0);
  cmd = argv[0];
  // "perf.bin"
  cl_perf_mode = strlen(cmd) > 8 && 
      (strcmp(cmd + strlen(cmd) - 8, "perf.bin") == 0);
  char *scm_filename = 0;
  if (argc > 1) { 
    scm_filename = argv[argc - 1];
    if (!cl_perf_mode) {
      if ((fin = fopen(scm_filename, "r")) == NULL) {
          perror(argv[argc - 1]); exit(1); }
      cl_interactive = 0;
      cl_verbose = argc > 2;
    } else {
      fin = stdin;
    }
  } else { fin = stdin; }
  cl_heap = cl_init(cl_private_memory_create(), CL_HEAP_SIZE);
  if (!cl_heap) exit(1);
  void *b = cl_heap;
  if (!scm_filename) scm_filename = "cli.scm";
  Id fn = cl_string_append(b, S(scm_filename), S(".perf"));
  cl_perf_mc = cl_shared_memory_create(cl_string_ptr(
      cl_retain(clNil, fn)), CL_PERF_MEM_SIZE);
  if (cl_perf_mc) { cl_perf = cl_perf_mc->base;  }
  else { printf("failed to create perf segment!\n"); exit(1); }
  int r = cl_init_memory(cl_perf, CL_PERF_MEM_SIZE);
  if (r == 2) exit(1);
  cl_add_perf_symbols(cl_perf);
  FILE* fb = fopen("boot.scm", "r");
  cl_repl(b, fb, 0);
  cl_repl(b, fin, cl_interactive);
  return 0;
}
