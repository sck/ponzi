/*
 * Copyright (c) 2010, 2011, Sven C. Koehler
 */

#define NEW 1

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
#include <semaphore.h>
#include <signal.h>


namespace ponzi {

#include "atomic.cpp"

#define PZ_RC_JUST_ALLOCATED 0xfffffff

#define WL const char *w, int l
#define WLB const char *w, int l, void *b
#define BP (char *)b


#if 1
#define CDS(w, va) printf("%s %lx %x %s %s\n", w, (size_t)b, PZ_ADR(va), pz_type_to_cp(PZ_TYPE(va)), pz_string_ptr(va));
#define CDS2(w, va_h, va) printf("%s %lx %x %x %s %s\n", w, (size_t)b, PZ_ADR(va_h), PZ_ADR(va), pz_type_to_cp(PZ_TYPE(va)), pz_string_ptr(va));
#else
#define CDS(w, va) 
#define CDS2(w, va_h, va)
#endif

#define PZ_VERSION "0.0.1"
#define PZ_GC_DEBUG  

int pid;

int debug = 0;

typedef size_t Id;

#define PZ_DB_MAGIC 0xF0F0
#define PZ_DB_VERSION 4

#define uchar unsigned char

#define PZ_ADR(va) int(va >> 32)
#define PZ_ADR_SET(va, v) va = (va & 0x00000000FFFFFFFF) | ((size_t) v << 32)
#define PZ_TYPE(va) (char)(va & 0x00000000000000FF)
#define PZ_TYPE_SET(va, v) va = (va & 0xFFFFFFFFFFFFFF00) | ((char) v)
#define PZ_LONG(va) size_t(va >> 8)
#define PZ_LONG_SET(va, v) va = (va & 0x00000000000000FF) | ((size_t) v << 8)
#define PZ_FLOAT(va) __pz_float(va)
#define PZ_FLOAT_SET(va, v) __pz_float_set(va, v)
#define PZ_CHAR(va) (uchar)(va >> 56)
#define PZ_CHAR_SET(va, v) va = (va & 0x00FFFFFFFFFFFFFF) | ((size_t) v << 56)

inline float __pz_float(Id va) {
  size_t fv = va >> 32;
  float f = (float &)fv;
  return f;
}

inline void __pz_float_set(Id &va, float v) {
  size_t i = (size_t &)v;
  va = (va & 0x00000000FFFFFFFF) | ((size_t)i  << 32);
}

static Id pzNil = {0}; 
static Id pzTrue = {0};
static Id pzTail = {0};
static Id pzError = {0}; 
static Id pzHeader = {0}; 

/*
 * Forwards
 */

#define PZ_DUMP_INSPECT 0x1
#define PZ_DUMP_DEBUG 0x2
#define PZ_DUMP_RECURSE 0x4

#define pz_string_ptr(s) __pz_string_ptr(__func__, __LINE__, b, s)
char *__pz_string_ptr(WLB, Id va_s);
void pz_print_dump(void *b, Id va, int flags);
const char *pz_type_to_cp(short int t);


#include "debug.cpp"

/*
 * Basic error handling
 */

typedef struct {
  char error_str[1024];
  int error_number;
} pz_error_t;

pz_error_t pz_error;
int pz_interactive = 1, pz_verbose = 1;
FILE *fin;

void pz_reset_errors() { memset(&pz_error, 0, sizeof(pz_error)); }
int pz_have_error() { return pz_error.error_str[0] != 0x0; }
#define CE(w) if (pz_have_error()) { printf("errors\n"); w; }
Id pz_handle_error_with_err_string(const char *ctx, 
    const char *error_msg, const char *handle) {
  char h[1024];
  if (handle != 0)  { snprintf(h, 1023, " '%s'", handle); } 
  else { strcpy(h, ""); }
  snprintf((char *)&pz_error.error_str, 1023, "%s%s: %s", ctx, h, error_msg);
  printf("error: %s\n", pz_error.error_str);
  pz_error.error_number = errno;
  return pzNil;
}

Id pz_handle_error(int check, const char *ctx, const char *handle) {
  if (!check) { return pzTrue; } 
  return pz_handle_error_with_err_string(ctx, strerror(errno), handle);
}

Id pz_handle_error_with_err_string_nh(const char *ctx, 
    const char *error_msg) { 
  return pz_handle_error_with_err_string(ctx, error_msg, 0);
}

/* 
 * Memory primitives 
 */

#define PZ_STATIC_ALLOC_SIZE 65536
#define PZ_VAR_COUNT 100000LL
#define PZ_MEM_SIZE (size_t)(PZ_VAR_COUNT * PZ_STATIC_ALLOC_SIZE)
#define PZ_PERF_MEM_SIZE (size_t)(1500LL * PZ_STATIC_ALLOC_SIZE)

#ifdef PZ_GC_DEBUG
#define PZ_GD_MAX_HIST 10

typedef struct {
  const char *where;
  int line;
  int is_new;
  int deleted;
  const char *retain_where;
  int retain_line;
  int retain_adr;
  size_t release_counter;
  size_t retain_counter;
  int retain_lines[PZ_GD_MAX_HIST];
  int release_lines[PZ_GD_MAX_HIST];
} pz_var_status_t;

pz_var_status_t pz_var_status[PZ_VAR_COUNT];

void pz_register_var(Id va, WL) {
  int adr = PZ_ADR(va);
  memset(&(pz_var_status[adr]), 0, sizeof(pz_var_status_t));
  pz_var_status[adr].where = w;
  pz_var_status[adr].line = l;
  pz_var_status[adr].is_new = 1;
}

void pz_unregister_var(Id va) {
  int adr = PZ_ADR(va);
  //memset(&(pz_var_status[adr]), 0, sizeof(pz_var_status_t));
  pz_var_status[adr].deleted = 1;
}
#else
#define pz_register_var(va, where, line)
#endif

void *pz_private_memory_create() {
  void *base = 0;
  base = mmap(0, PZ_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 
      -1, (off_t)0);
  if (!pz_handle_error(base == MAP_FAILED, "mmap", 0)) return 0;
  return base;
}

typedef struct {
  int fd;
  void *base;
  char *filename;
  size_t size;
} pz_shm_t;

pz_shm_t *pz_perf_mc;

int pz_does_filename_exist(char *fn) {
  struct stat st;
  return stat(fn, &st) != -1;
}

void pz_ensure_filename(char *fn) {
  if (!pz_does_filename_exist(fn)) close(open(fn, O_CREAT, 0777)); 
}

pz_shm_t *pz_shared_memory_create(char *fn, size_t size) {
  pz_ensure_filename(fn);  
  pz_shm_t *mc = (pz_shm_t *)calloc(1, sizeof(pz_shm_t));
  if (!mc) {
    pz_handle_error_with_err_string_nh( __func__, "Out of memory");
    return 0;
  }

  mc->filename = fn;
  mc->size = size;
  if (!pz_handle_error((mc->fd = open(fn, O_RDWR, (mode_t)0777)) == -1, 
      "open", fn)) goto open_failed;
  if (!pz_handle_error(lseek(mc->fd, mc->size - 1, SEEK_SET) == -1, 
      "lseek", fn)) goto failed;
  if (!pz_handle_error(write(mc->fd, "", 1) != 1, "write", fn)) goto failed;
  mc->base = mmap(0, mc->size, PROT_READ | PROT_WRITE, MAP_SHARED, mc->fd, 
      (off_t)0);
  if (!pz_handle_error(mc->base == MAP_FAILED, "mmap", fn)) goto failed;

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
// lock + rc + type + compiled + flags
#define RCS (sizeof(int)+sizeof(int)+sizeof(short int)+sizeof(void*)+sizeof(uchar))
#define rc_t int
#define PZ_CELL_SIZE int(PZ_STATIC_ALLOC_SIZE - RCS)


#define PZ_TYPE_BOOL 0
#define PZ_TYPE_FLOAT 1
#define PZ_TYPE_LONG 2
#define PZ_TYPE_CHAR 3
#define PZ_TYPE_SPECIAL 4
#define PZ_BASIC_TYPE_BOUNDARY 5

#define pz_string_size_t short int

typedef struct {
  int lock_pid;
  int rc_dummy;  
  Id first_free;
  size_t heap_size;
  size_t total_size;
  int magic;
  int version;
  Id symbol_interns;
  Id string_interns;
  Id globals;
  Id string_constants;
  Id string_constants_dict;
  Id perf_dict;
} pz_mem_descriptor_t;

typedef struct {
  int lock_pid;
  int rc_dummy; 
  Id next;
  size_t size;
} pz_mem_chunk_descriptor_t;

#define PZ_VA_START 7
size_t pz_header_size() { return PZ_STATIC_ALLOC_SIZE * PZ_VA_START; }
Id pz_header_size_ssa() { Id a = 0; PZ_ADR_SET(a, PZ_VA_START); return a; }
#define pz_md __pz_md(b)
void *pz_heap = 0;
void *pz_perf = 0;

pz_mem_descriptor_t *__pz_md(void *b) { return (pz_mem_descriptor_t *)b; }


#define VA_TO_PTR0(va) \
  ((va) ? ((char *)b) + RCS + ((size_t)PZ_ADR(va) * PZ_STATIC_ALLOC_SIZE) : 0) 
#define PTR_TO_VA(va, p) \
  PZ_ADR_SET(va, (int)(((p) - RCS - (char *)b) / PZ_STATIC_ALLOC_SIZE));

#define P_0_R(p, r) if (!(p)) { printf("From %s:%d\n", __func__, __LINE__); return (r); }
#define P_0_R2(w, l, p, r) if (!(p)) { printf("From %s:%d\n", w, l); return (r); }
#define VA_0_R(va, r) if (!(va)) { return (r); }
#define VA_TO_PTR(va) (__ca(b, va, __func__, __LINE__) ? VA_TO_PTR0(va) : 0 )
#define VA_TO_PTR2(va) (__ca(b, va, w, l) ? VA_TO_PTR0(va) : 0 )


//#define SPEED 

#ifdef SPEED
#define __ca(b, va, w, l) 1
#else
int __ca(void *b, Id va, WL) {
  char *p0 = VA_TO_PTR0(va); P_0_R(p0, 1); 
  rc_t *rc = (rc_t *)(p0 - RCS + sizeof(int));
  if ((*rc) == 0) { printf("[%s:%d] error: VA #x%x is not allocated!\n", w, l, PZ_ADR(va)); abort(); }
  return 1;
}
#endif


Id cb(int i) { return i ? pzTrue : pzNil; }

#define pz_md_first_free (pz_mem_chunk_descriptor_t *)VA_TO_PTR0((va_first = pz_md->first_free))

int pz_vars_free(void *b) {
    return (pz_md->total_size - pz_md->heap_size) / PZ_STATIC_ALLOC_SIZE; }

int pz_vars_total(void *b) { return pz_md->total_size / PZ_STATIC_ALLOC_SIZE; }
  

#define PZ_TYPE_STRING 5
#define PZ_TYPE_SYMBOL 6
#define PZ_TYPE_CFUNC 7
#define PZ_TYPE_PAIR 8
#define PZ_TYPE_HASH 9
#define PZ_TYPE_HASH_PAIR 10
#define PZ_TYPE_ARRAY 11
#define PZ_TYPE_REGEXP 12
#define PZ_TYPE_MAX 12

#define pz_ary_len(b, a) __pz_ary_len(__func__, __LINE__, b, a)
int __pz_ary_len(WLB, Id va_ary);

//int cnil(Id i) { return i == pzNil || PZ_TYPE(i) < PZ_BASIC_TYPE_BOUNDARY; }
#define cnil(va) __cnil(b, va)
int __cnil(void *b, Id i) { 
    return i == pzNil || 
    (PZ_TYPE(i) == PZ_TYPE_ARRAY && pz_ary_len(b, i) == 0); }


#define pz_retain(from, va) __pz_retain(__func__, __LINE__, b, from, va)
#define pz_retain0(va) __pz_retain(__func__, __LINE__, b, pzNil, va)
#define pz_retain2(from, va) __pz_retain(w, l, b, from, va)


Id __pz_retain(WLB, Id from, Id va);


#define pz_lock_header() __pz_lock_header(__func__, __LINE__, b)
int __pz_lock_header(WLB);
#define pz_unlock_header() __pz_unlock_header(__func__, __LINE__, b)
int __pz_unlock_header(WLB);

#define PZ_HEADER_DS(name, type) \
    PZ_ADR_SET(pz_md->name, ++adr_counter); \
    PZ_TYPE_SET(pz_md->name, type);  \
    pz_retain0(pz_retain0(pz_md->name)); \

#define PZ_HEAP_SIZE \
    ((PZ_MEM_SIZE / PZ_STATIC_ALLOC_SIZE) * PZ_STATIC_ALLOC_SIZE)

int __pz_init_memory(void *b, size_t size) {
  size_t s = size - pz_header_size();
  Id va_first;
  if (pz_md->magic != PZ_DB_MAGIC) {
    pz_md->first_free = pz_header_size_ssa();
    pz_md->total_size = s;
    pz_mem_chunk_descriptor_t *c = pz_md_first_free;
    c->next = 0;
    c->lock_pid = 0;
    c->size = s;

    int adr_counter = 0;

    PZ_HEADER_DS(symbol_interns, PZ_TYPE_HASH);
    PZ_HEADER_DS(string_interns, PZ_TYPE_HASH);
    PZ_HEADER_DS(globals, PZ_TYPE_HASH);
    PZ_HEADER_DS(string_constants, PZ_TYPE_ARRAY);
    PZ_HEADER_DS(string_constants_dict, PZ_TYPE_HASH);
    PZ_HEADER_DS(perf_dict, PZ_TYPE_HASH);
    //PZ_HEADER_DS(gc, PZ_TYPE_HASH); // empty hash, just used for locking.

    if (PZ_VA_START != adr_counter + 1) {
      printf("Error: PZ_VA_START is %d but it should be %d\n",
          PZ_VA_START, adr_counter + 1);
      abort();
    }

    pz_md->magic = PZ_DB_MAGIC;
    pz_md->version = PZ_DB_VERSION;
    return 1;
  } else if (pz_md->version != PZ_DB_VERSION) {
    char es[1024]; 
    snprintf(es, 1023, "DB version is %d.  Current version is %d.", 
        pz_md->version, PZ_DB_VERSION);  
    pz_handle_error_with_err_string_nh(__func__, es);
    return 2;
  }
  return 0;
}

int pz_init_memory(void *b, size_t size) {
  PZ_TYPE_SET(pzHeader, PZ_TYPE_HASH); // fake hash
  PZ_ADR_SET(pzHeader, 0);
  pz_lock_header();
  int r = __pz_init_memory(b, size);
  pz_unlock_header();
  return r;
}

int pz_perf_mode = 0;

void pz_alloc_debug(void *b, char *p, short int type) {
  //return;
  //if (!pz_perf_mode || b != pz_perf) return;
  if (!debug) return;
  const char *n = b == pz_perf ? "perf" : "scheme";
  printf("[%s:%lx] alloc %lx type: %s\n", n, (size_t)b, (size_t)p, 
      pz_type_to_cp(type));
}

inline Id pz_atomic_cas_id(volatile Id *v, Id _new, Id old) {
  Id r;
  r = pz_atomic_casq((size_t *)v, _new, old); 
  return r;
}

int pz_lock_debug = 0;

#define pz_lock_p(p) __pz_lock_p(__func__, __LINE__, p)
int __pz_lock_p(WL, char *_p) { 
  if (!_p) return 0;
  char *p = _p - RCS;
  if (pz_lock_debug) printf("[%s:%d] lock: %lx\n", w, l, (size_t)p);
  size_t c = 0;
  int r;
retry: 
  c++;
  int *pl = (int *)p;
  int ov = *pl;
  if (ov) { 
    if (ov == pid) return 1;
    goto do_retry; 
  }
set_pid:
  {}
  r = pz_atomic_casl(pl, pid, ov);
  if (ov != r) goto do_retry; 
  return 1;

do_retry:
  if (c > 10000000) {
    c = 0;
    printf("[%s:%d] Checking for process %d\n", w, l, ov);
    if (kill(ov, SIGWINCH)  == -1) {
      printf("Process does not exist anymore... ignore.\n");
      goto set_pid;
    }
  }
  goto retry;
}

#define pz_unlock_p(p) __pz_unlock_p(__func__, __LINE__, p) 
int __pz_unlock_p(WL, char *_p) { 
  if (!_p) return 0;
  char *p = _p - RCS;
  if (pz_lock_debug) printf("[%s:%d] unlock: %lx\n", w, l, (size_t)p);
  int *i = (int *)p; 
  if (pz_lock_debug && *i != pid) { printf("DUH: lock: %d\n", *i); }
  *i = 0; return 1; }

#define LI if (!va || PZ_TYPE(va) < PZ_BASIC_TYPE_BOUNDARY) { return 0; }; \
  char *p0 = VA_TO_PTR0(va); \
  P_0_R(p0, 0); char *p = (char *)p0;


#define pz_lock_va(va) __pz_lock_va(__func__, __LINE__, b, va)
int __pz_lock_va(WLB, Id va) { LI; return __pz_lock_p(w, l, p); }
#define pz_unlock_va(va) __pz_unlock_va(__func__, __LINE__, b, va)
int __pz_unlock_va(WLB, Id va) { LI; return __pz_unlock_p(w, l, p); }

#define pz_symbol_interns pz_md->symbol_interns
#define pz_string_interns pz_md->string_interns
#define pz_globals pz_md->globals
#define pz_string_constants pz_md->string_constants
#define pz_string_constants_dict pz_md->string_constants_dict
#define pz_perf_dict pz_md->perf_dict

int __pz_lock_header(WLB) { return __pz_lock_va(w, l, b, pzHeader); }
int __pz_unlock_header(WLB) { return __pz_unlock_va(w, l, b, pzHeader); }

int pz_alloc_locked = 0;
Id __pz_valloc(void *b, const char *where, short int type) {
  Id va_first;
retry_start:
  {}
  pz_mem_chunk_descriptor_t *c = pz_md_first_free; 
  if (!c) return pz_handle_error_with_err_string_nh(where, "1: Out of memory");
  pz_alloc_locked = 1;
  Id r = { 0x0 };
  if (c->size < PZ_STATIC_ALLOC_SIZE) {
    r = pz_handle_error_with_err_string_nh(where, "2: Out of memory");
    goto finish;
  }
  if (c->size == PZ_STATIC_ALLOC_SIZE) {
    // chunk size ==  wanted size
    Id ns = pz_atomic_cas_id(&pz_md->first_free, c->next, va_first); 
    if (ns != va_first) { printf("alloc first failed\n"); goto retry; }
    PTR_TO_VA(r, (char *)c);
  } else {
    size_t ns, os;
    os = c->size;
    ns = pz_atomic_sub(&c->size, PZ_STATIC_ALLOC_SIZE);
    if (ns != os) { printf("alloc sub failed\n"); goto retry; }
    PTR_TO_VA(r, (char *)c + c->size);
  }
  if (!c->next) { pz_md->heap_size += PZ_STATIC_ALLOC_SIZE; }
  if (r) { 
    PZ_TYPE_SET(r, type); 
    pz_lock_va(r);
    char *p = VA_TO_PTR0(r);
    rc_t *rc = (rc_t *) (p - RCS + sizeof(int));
    *rc = PZ_RC_JUST_ALLOCATED;
    short int *t = (short int *)(p - sizeof(short int) - sizeof(uchar));
    *t = type;
    uchar *f = (uchar *)(p - sizeof(uchar));
    f = 0x0;
    void **df = (void **)(p - sizeof(uchar) - sizeof(void*));
    *df = 0x0;
    pz_unlock_va(r);
  }
finish:
  return r;

retry:
  goto retry_start;
}

Id pz_valloc(void *b, const char *where, short int type) {
  pz_alloc_locked = 0;
  pz_lock_header();
  Id r = __pz_valloc(b, where, type);
  pz_unlock_header();
  return r;
}

int pz_zero(void *b, Id va, int size) { 
  char *p = VA_TO_PTR0(va); P_0_R(p, 0); 
  memset(p, 0, size == 0 ? 20 : size); 
  return 1;}

#define PZ_ALLOC(va, type) va = pz_valloc(b, __func__, type); VA_0_R(va, pzNil);

#define PZ_NO_BASIC_TYPES(v, rv) \
  if (!va || PZ_TYPE(va) < PZ_BASIC_TYPE_BOUNDARY) { return rv; }; 

#define RCI0(rv, rv2) \
  PZ_NO_BASIC_TYPES(va, rv); \
  char *p0 = VA_TO_PTR0(va); \
  void **df = (void **)(p0 - sizeof(uchar) - sizeof(void*)); \
  uchar *flags = (uchar *)(p0 - sizeof(uchar)); \
  P_0_R(p0, rv2); rc_t *rc = (rc_t *)(p0 - RCS + sizeof(int)); \
  rc = rc; flags = flags; df = df; 

#define RCI RCI0(va, pzNil);

void *pz_have_dispatched_func_p(void *b, Id va) { RCI0(0, 0); return *df; }
int pz_set_dispatched_func(void *b, Id va, void *f) { 
    RCI0(0, 0); *df = f; return 1; }


Id show_rc(const char *m, void *b, Id va) {
  if (!debug) return pzNil;
  RCI; 
  printf("%s #x%x rc %d\n", m, PZ_ADR(va), *rc);
  return pzNil;
}

#define PZ_GCF_RETURN 0x1

#define PZ_GC_RETURN_VALUE_P ((*flags & PZ_GCF_RETURN) > 0)
#define PZ_GC_CLEAR_RV *flags = *flags & 0xFE

Id pz_gc_mark_return_value(void *b, Id va) {
    RCI; *flags = *flags | PZ_GCF_RETURN; return va; }

int pz_free(void *b, Id va) {
  //show_rc("pz_free", b, va);
  int t = PZ_TYPE(va);
  if (t == PZ_TYPE_BOOL || t == PZ_TYPE_FLOAT || t == PZ_TYPE_LONG) return 0;
  char *used_chunk_p = VA_TO_PTR(va); P_0_R(used_chunk_p, 0);
  pz_mem_chunk_descriptor_t *mcd_used_chunk = 
      (pz_mem_chunk_descriptor_t *)used_chunk_p;
  pz_lock_header();
  mcd_used_chunk->size = PZ_STATIC_ALLOC_SIZE;
  mcd_used_chunk->rc_dummy = 0;
  while (1) {
    Id o = mcd_used_chunk->next = pz_md->first_free;
    Id r = pz_atomic_cas_id(&pz_md->first_free, va, o);
    if (o == r) goto finish;
    printf("free failed! try again\n");
  }
finish:
  pz_unlock_header();
  return 1;
}

/*
 * Register types.
 */

Id pz_long(size_t i) { 
    Id va = 0; PZ_TYPE_SET(va, PZ_TYPE_LONG); PZ_LONG_SET(va, i); return va; }

Id pz_float(float f) { 
    Id va = 0; PZ_TYPE_SET(va, PZ_TYPE_FLOAT); PZ_FLOAT_SET(va, f); return va; }

Id pz_char(char c) { 
    Id va = 0; PZ_TYPE_SET(va, PZ_TYPE_CHAR); PZ_CHAR_SET(va, c); return va; }

Id cn(Id v) { return PZ_TYPE(v) == PZ_TYPE_BOOL ? pz_long(v ? 1 : 0) : v; }

/*
 * Basic types 
 */


const char *pz_types_s[] = {"bool", "float", "long", "char", "special", "string",
    "symbol", "cfunc", "cons", "hash", "hash-pair", "vector"};

const char *pz_type_to_cp(short int t) {
  if (t > PZ_TYPE_MAX || t < 0) { return "<unknown>"; }
  return pz_types_s[t];
}

int pz_is_string(Id va) { 
    return PZ_TYPE(va) == PZ_TYPE_SYMBOL || PZ_TYPE(va) == PZ_TYPE_STRING; }
int pz_is_number(Id va) { 
    return PZ_TYPE(va) == PZ_TYPE_FLOAT || PZ_TYPE(va) == PZ_TYPE_LONG; }
inline int c_type(int t) { return t == PZ_TYPE_SYMBOL ? PZ_TYPE_STRING : t;}
inline int pz_is_type_i(Id va, int t) { return c_type(PZ_TYPE(va)) == c_type(t); }
#define S(s) pz_string_new_c(b, s)
#define IS(s) pz_intern_cp(b, s)
#define ISS(s) pz_intern_cp(b, s, 1)


#define PZ_CHECK_TYPE2(w, l, va, _type, r) \
  if (!pz_is_type_i((va), (_type))) { \
    char es[1024]; \
    snprintf(es, 1023, "(%s:%d) Invalid type: Expected type '%s', " \
        "have: '%s'", \
        w, l, \
        pz_type_to_cp((_type)), pz_type_to_cp(PZ_TYPE(va)));  \
    pz_handle_error_with_err_string_nh(__func__, es); \
    return (r); \
  }

#define PZ_CHECK_TYPE(va, _type, r) \
    PZ_CHECK_TYPE2(__func__, __LINE__, va, _type, r)

#define PZ_CHECK_ERROR(cond,msg,r) \
  if ((cond)) { pz_handle_error_with_err_string_nh(__func__, (msg)); return (r); }

#define __PZ_TYPED_VA_TO_PTR(ct, ptr, va, type, r, check) \
  PZ_CHECK_TYPE((va), (type), (r)); (ptr) = (ct *)check((va)); P_0_R((ptr), (r));
#define __PZ_TYPED_VA_TO_PTR2(ct, ptr, va, type, r, check) \
  PZ_CHECK_TYPE2(w, l, (va), (type), (r)); (ptr) = (ct *)check((va)); P_0_R((ptr), (r));
#define PZ_TYPED_VA_TO_PTR(ct, p,v,t,r) __PZ_TYPED_VA_TO_PTR(ct, p,v,t,r,VA_TO_PTR)
#define PZ_TYPED_VA_TO_PTR2(ct, p,v,t,r) __PZ_TYPED_VA_TO_PTR2(ct, p,v,t,r,VA_TO_PTR2)
#define PZ_TYPED_VA_TO_PTR0(ct, p,v,t,r) __PZ_TYPED_VA_TO_PTR(ct, p,v,t,r,VA_TO_PTR0)

size_t pz_max(size_t a, size_t b) { return a > b ? a : b; }
size_t pz_min(size_t a, size_t b) { return a < b ? a : b; }

#ifdef PZ_GC_DEBUG

void __pz_var_info(void *b, pz_var_status_t *s, const char *m, rc_t *rc, Id r) {
   char rcd[1024];
   if (*rc < PZ_RC_JUST_ALLOCATED) snprintf((char*)&rcd, 1023, "%d", *rc);
   else snprintf((char*)&rcd, 1023, "%s", "<just-allocated>");
   printf("%s: %s %s:%d ", m, rcd, s->where, s->line );
   if (*rc > 0) pz_print_dump(b, r, PZ_DUMP_DEBUG | PZ_DUMP_RECURSE);
   if (s->retain_where) {
     printf("retain from %s:%d %x %ld:%ld", 
         s->retain_where,
         s->retain_line, s->retain_adr, s->retain_counter, 
         s->release_counter);
   }
   size_t i;
   printf(" rt ");
   for (i = 0; i < pz_min(s->retain_counter, PZ_GD_MAX_HIST); i++) 
       printf("%d ", s->retain_lines[i]);
   printf(" rl ");
   for (i = 0; i < pz_min(s->release_counter, PZ_GD_MAX_HIST); i++) 
       printf("%d ", s->release_lines[i]);
   printf("\n");
}
void pz_md_print_var_info(void *b, const char *m, rc_t *rc, Id r, int silent, 
    int only_new) {
  pz_var_status_t *s = &pz_var_status[PZ_ADR(r)];
  if (!silent) {
    if (s->is_new)  __pz_var_info(b, s, m, rc, r);
    else if (s->deleted) __pz_var_info(b, s, "WHOA: ALREADY DELETED", rc, r);
  }
  if (only_new) pz_var_status[PZ_ADR(r)].is_new = 0;
}

#endif


/*
 * Reference counting.
 */

int pz_ary_free(void *b, Id);
int pz_pair_free(void *b, Id);
int pz_ht_free(void *b, Id);

Id pz_delete(void *b, Id va);
#define pz_release(va) __pz_release(__func__, __LINE__, b, va)
#define pz_release_no_delete(va) __pz_release(__func__, __LINE__, b, va, 0)
Id __pz_release(WLB, Id va, int do_delete = 1) { 
  RCI; 
  int rv, nv, ov;
  do {
    ov =  *rc;
#ifdef PZ_GC_DEBUG
    if (*rc <= 1) {
      pz_md_print_var_info(b, "auto-delete", rc, va, 0, 0);
      printf("---- last delete was: %s %d\n", w, l);
    }
#endif
    PZ_CHECK_ERROR((*rc <= 1), "Reference counter is already 0!", pzNil);
#ifdef PZ_GC_DEBUG
    if (ov == PZ_RC_JUST_ALLOCATED) {
      printf("[%s:%d] ", w, l);
      pz_md_print_var_info(b, "release without retain", rc, va, 0, 0);
      return pzNil;
    }
#endif
    if (ov == 2 && (!do_delete || PZ_GC_RETURN_VALUE_P)) { 
      nv = PZ_RC_JUST_ALLOCATED; } 
    else { nv = ov - 1; }
    rv = pz_atomic_casl(rc, nv, ov);
  } while (rv != ov);
  if (PZ_GC_RETURN_VALUE_P) PZ_GC_CLEAR_RV;
#ifdef PZ_GC_DEBUG
  size_t rrc = pz_var_status[PZ_ADR(va)].release_counter++;
  if (rrc < PZ_GD_MAX_HIST) {
    pz_var_status[PZ_ADR(va)].release_lines[rrc] = l;
  }
#endif
  //if (debug) {
  //  printf("[%s:%d] rc %d ", w, l, *rc); D("release", va);
  //  show_rc("", b, va);
  //}
  if (*rc == 1) {
    //if (debug) {
    //  printf("[%s:%d] ", w, l);
    //  pz_md_print_var_info(b, "auto-delete", rc, va, 0, 0);
    //}
    pz_delete(b, va);
#ifdef PZ_GC_DEBUG
    pz_unregister_var(va);
#endif
  }
  return va;
}

#define pz_release_ja(va) __pz_release_ja(__func__, __LINE__, b, va)
Id __pz_release_ja(WLB, Id va) { 
  __pz_retain(w, l, b, pzNil, va);
  __pz_release(w,l, b, va);
  return va; 
}
int pz_rx_free(void *b, Id va_rx);

#define RetainGuard(from, va) __RetainGuard guard(__func__, __LINE__, b, from, va)
#define RetainGuard0(va) __RetainGuard guard(__func__, __LINE__, b, pzNil, va)
#define RetainGuard0n(n, va) __RetainGuard n(__func__, __LINE__, b, pzNil, va)
#define RG(n) __RetainGuard n(__func__, __LINE__, b)
class __RetainGuard {
  const char *w;
  int l;
  void *b;
  Id va;
public:
  __RetainGuard(const char *_w, int _l, void *_b, Id from, Id _va) : 
      w(_w), l(_l), b(_b), va(_va) { 
      __pz_retain(w, l, b, from, va); }
  __RetainGuard(const char *_w, int _l, void *_b) : 
      w(_w), l(_l), b(_b), va(pzNil) { }
  ~__RetainGuard() { __pz_release(w, l, b, va); }
  Id& operator=(const Id& nva) {
    __pz_release(w, l, b, va);
    va = nva;
    __pz_retain(w, l, b, pzNil, va);
    return va;
  }
};


Id pz_delete(void *b, Id va) { 
  RCI; 
  if ((*rc) == 0x0) return pzNil; // ignore, so one can jump to random address!
  //show_rc("pz_delete", b,va);
  PZ_CHECK_ERROR((*rc != 1), "Cannot delete, rc != 0!", pzNil);
  switch (PZ_TYPE(va)) {
    case PZ_TYPE_PAIR: pz_pair_free(b, va); break;
    case PZ_TYPE_ARRAY: pz_ary_free(b, va); break;
    case PZ_TYPE_HASH: pz_ht_free(b, va); break;
    case PZ_TYPE_HASH_PAIR: pz_free(b, va);  break;
    case PZ_TYPE_REGEXP: pz_rx_free(b, va); break; 
    default: pz_free(b, va); break;
  }
  (*rc) = 0x0;
  return pzTrue;
}

size_t __pz_mem_dump(void *b, int silent) {
  size_t entries = pz_md->heap_size / PZ_STATIC_ALLOC_SIZE;
  size_t mem_start = pz_md->total_size + pz_header_size() - 
      pz_md->heap_size;
#ifndef PZ_GC_DEBUG
  int debug = 0;
#endif

  if (!silent && debug) printf("totalsize: %ld\n", pz_md->total_size);
  char *p = BP + mem_start + sizeof(int);
  size_t i;
  size_t active_entries = 0;
  if (!silent && debug) printf("[%lx] mem dump: entries: %ld\n", (size_t)b, entries);
  for (i = 0; i < entries; ++i, p += PZ_STATIC_ALLOC_SIZE) {
    rc_t *rc = (rc_t *)p;
    if (*rc > 0) {
      active_entries++;
      short int *t = (short int *) (p + sizeof(int));
      Id r = 0;
      PTR_TO_VA(r, (char *)p - sizeof(int) + RCS);
      PZ_TYPE_SET(r, *t);
#ifdef PZ_GC_DEBUG
      pz_md_print_var_info(b, "NEW", rc, r, (!debug || silent) , 1);
#endif
    }
  }
#ifdef PZ_GC_DEBUG
  if (!silent && debug) printf("active: %ld\n", active_entries);
#endif
  return active_entries;
}

size_t pz_mem_dump(void *b) { return __pz_mem_dump(b, 0); }
size_t pz_active_entries(void *b) { return __pz_mem_dump(b, 1); }

Id __pz_retain(WLB, Id va_from, Id va) { 
  RCI;
#ifdef PZ_GC_DEBUG
  if (*rc != PZ_RC_JUST_ALLOCATED && *rc <= 1) {
    pz_md_print_var_info(b, "Retain of what has already been freed", 
        rc, va, 0, 0);
  }
  pz_var_status[PZ_ADR(va)].retain_where = w;
  pz_var_status[PZ_ADR(va)].retain_line = l;
  pz_var_status[PZ_ADR(va)].retain_adr = PZ_ADR(va_from);
  size_t rrc = pz_var_status[PZ_ADR(va)].retain_counter++;
  if (rrc < PZ_GD_MAX_HIST) {
    pz_var_status[PZ_ADR(va)].retain_lines[rrc] = l;
  }
#endif
  int rv, ov, nv;
  do {
    ov =  *rc;
    nv = ov == PZ_RC_JUST_ALLOCATED ? 2 : ov + 1;
    rv = pz_atomic_casl(rc, nv, ov);
  } while (rv != ov);
  return va; 
}

/*
 * String
 */

#define PZ_STR_MAX_LEN (int)(PZ_CELL_SIZE - sizeof(pz_string_size_t))

int pz_strdup(void *b, Id va_dest, const char *source, pz_string_size_t l) {
  char *p; PZ_TYPED_VA_TO_PTR0(char, p, va_dest, PZ_TYPE_STRING, 0);
  PZ_CHECK_ERROR((l + 1 > PZ_STR_MAX_LEN), "strdup: string too large", 0);
  *(pz_string_size_t *) p = l;
  p += sizeof(pz_string_size_t);
  memcpy(p, source, l);
  p += l;
  (*p) = 0x0;
  return 1;
}

#define pz_string_new(b, s, l) __pz_string_new(__func__, __LINE__, b, s, l)
Id __pz_string_new(WLB, const char *source, pz_string_size_t len) { 
  Id va; PZ_ALLOC(va, PZ_TYPE_STRING);
  if (!pz_strdup(b, va, source, len)) return pzNil;
  pz_register_var(va, w, l);
  return va;
}

#define pz_string_new_c(b, s) __pz_string_new_c(__func__, __LINE__, b, s)
Id __pz_string_new_c(WLB, const char *source) { 
    return __pz_string_new(w, l, b, source, strlen(source)); }

Id __pz_snn(void *b, Id n, const char *f) { 
  int i = PZ_TYPE(n) == PZ_TYPE_LONG;
  char ns[1024]; 
  i ? snprintf(ns, 1023, f, PZ_LONG(n)) : 
      snprintf(ns, 1023, "%f", PZ_FLOAT(n));
  return S(ns);
}

Id pz_string_new_number(void *b, Id n) { return __pz_snn(b, n, "%d"); }
Id pz_string_new_hex_number(void *b, Id n) { return __pz_snn(b, n, "0x%x"); }

typedef struct { 
  char *s; 
  pz_string_size_t l; 
  int dump_recurse;
  int dump_inspect;
  int dump_debug;
} pz_str_d;
int sr = 0;
#define PZ_ACQUIRE_STR_D(n,va,r) \
  pz_str_d n; sr = pz_acquire_string_data(b, va, &n); P_0_R(sr, r);
#define PZ_ACQUIRE_STR_D2(n,va,r) \
  pz_str_d n; sr = pz_acquire_string_data(b, va, &n); P_0_R2(w, l, sr, r);
#define pz_acquire_string_data(b, s, d) \
  __pz_acquire_string_data(__func__, __LINE__, b, s, d)

inline int __pz_acquire_string_data(WLB, Id va_s, pz_str_d *d) { 
  char *s; PZ_TYPED_VA_TO_PTR2(char, s, va_s, PZ_TYPE_STRING, 0);
  d->s = s + sizeof(pz_string_size_t); d->l = *(pz_string_size_t *) s; 
  return 1;
}

#define pz_string_sub_str_new(b, s, st, c) \
    __pz_string_sub_str_new(__func__, __LINE__, b, s, st, c)
Id __pz_string_sub_str_new(WLB, Id s, int start, 
    int _count) {
  PZ_ACQUIRE_STR_D(dt, s, pzNil);
  if (start > dt.l) start = dt.l;
  if (start < 0) start = 0;
  int count = (_count < 0) ? (dt.l + _count + 1) - start : _count;
  if (count < 0) count = 0;
  if (count > dt.l - start) count = dt.l - start;
  char sym[dt.l + 1];
  memcpy(&sym, dt.s + start, count);
  return __pz_string_new(w, l, b, (char *)&sym, count);
}

#define pz_string_new_0(b) __pz_string_new_0(__func__, __LINE__, b)
Id __pz_string_new_0(WLB) { return __pz_string_new(w, l, b, "", 0); }

char *__pz_string_ptr(WLB, Id va_s) { 
  if (cnil(va_s)) return 0;
  PZ_ACQUIRE_STR_D2(ds, va_s, 0x0); 
  char *r = ds.s; 
  return r; 
}

Id pz_string_append(void *b, Id va_d, Id va_s) {
  RetainGuard0(va_s);
  PZ_ACQUIRE_STR_D(dd, va_d, pzNil); PZ_ACQUIRE_STR_D(ds, va_s, pzNil);
  long l = dd.l + ds.l;
  PZ_CHECK_ERROR((l + 1 > PZ_STR_MAX_LEN), "append: string too large", pzNil);
  memcpy(dd.s + dd.l, ds.s, ds.l);
  *(pz_string_size_t *) (dd.s - sizeof(pz_string_size_t)) = l;
  dd.s += l;
  (*dd.s) = 0x0;
  return va_d;
}

int pz_string_hash(void *b, Id va_s, size_t *hash) {
  PZ_ACQUIRE_STR_D(ds, va_s, 0); char *s = ds.s;
  size_t v;
  pz_string_size_t i;
  for (v = 0, i = 0; i++ < ds.l; s++) { v = *s + 31 * v; }
  (*hash) = v;
  return 1;
}

int pz_string_len(void *b, Id va_s) {
  PZ_ACQUIRE_STR_D(ds, va_s, 0); return ds.l; }

Id pz_string_char_at(void *b, Id va_s, long pos) {
  PZ_ACQUIRE_STR_D(ds, va_s, 0); 
  if (pos + 1 > ds.l) return pzNil;
  return pz_char(*(ds.s + pos)); 
}

#define pz_string_equals_cp_i(s, sb)  \
    __pz_string_equals_cp_i(__func__, __LINE__, b, s, sb)
int __pz_string_equals_cp_i(WLB, Id va_s, const char *sb) {
  PZ_ACQUIRE_STR_D2(ds, va_s, 0); 
  long bl = strlen(sb);
  if (ds.l != bl) { return 0; }
  pz_string_size_t i;
  for (i = 0; i < ds.l; i++) { if (ds.s[i] != sb[i]) return 0; }
  return 1;
}

char pz_hex_to_char(const char *s) {
  char hn[3];
  hn[0] = s[0]; hn[1] = s[1]; hn[2] = 0x0;
  char *ep;
  long l = strtol((char *)&hn, &ep, 16);
  if (ep && *ep == '\0') return char(l);
  return '?';
}

Id pz_string_unquote(void *b, Id va_s) {
  PZ_ACQUIRE_STR_D(dt, va_s, 0); 
  pz_retain0(va_s);
  char r[16384];
  int i, ri, l = dt.l; 
  for (ri = i = 0; i < dt.l && ri < 16300; ++i, ++ri, --l) {
    uchar c = dt.s[i];
    if (c == '\\' && l > 1) {
      uchar c2 = dt.s[++i]; --l;
      if (c2 == 'n') r[ri] = '\n';
      else if (c2 == 'r') r[ri] = '\r';
      else if (c2 == '\\') r[ri] = '\\';
      else if (c2 == 'x' && l > 2) { // \xFF
        r[ri] = pz_hex_to_char(dt.s + i + 1);
        i += 2;
      }
    } else r[ri] = dt.s[i];
  }
  r[ri] = 0x0;
  pz_release(va_s);
  return pz_string_new(b, (const char *)&r, ri);
}

void __cp(char **d, char **s, size_t l, int is) {
    memcpy(*d, *s, l); (*d) += l; if (is) (*s) += l; }

int pz_string_starts_with_cp_i(void *b, Id va_s, const char *q) {
  PZ_ACQUIRE_STR_D(ds, va_s, 0); 
  pz_str_d dq;
  dq.l = strlen(q);
  dq.s = (char *)q;
  if (dq.l > ds.l) return 0;
  return strncmp(ds.s, dq.s, dq.l) == 0;
}

Id pz_string_replace(void *b, Id va_s, Id va_a, Id va_b) {
  RetainGuard0(va_s);
  RetainGuard0n(__ga, va_a);
  RetainGuard0n(__gb, va_b);
  PZ_ACQUIRE_STR_D(ds, va_s, pzNil); PZ_ACQUIRE_STR_D(da, va_a, pzNil); 
  PZ_ACQUIRE_STR_D(db, va_b, pzNil); 
  Id va_new = pz_string_new_0(b); PZ_ACQUIRE_STR_D(dn, va_new, pzNil);
  char *dp = dn.s, *sp = ds.s; P_0_R(dp, pzNil)
  long i, match_pos = 0;
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
  *(pz_string_size_t *)(dn.s - sizeof(pz_string_size_t)) = dp - dn.s;
  return va_new;
}

/*
 * general var handling
 */

size_t pz_hash_var(void *b, Id va) {
  if (PZ_TYPE(va) == PZ_TYPE_STRING) {
    size_t h = 0;
    pz_string_hash(b, va, &h);
    return h;
  }
  return va;
}

Id cnil2(void *b, Id i) { 
    return PZ_TYPE(i) == PZ_TYPE_ARRAY && pz_ary_len(b, i) == 0 ? pzNil : i; }


int pz_ary_equals_i(void *b, Id a, Id o);

#define pz_eq_i(a, o) __pz_equals_i(b, a, o)
#define pz_equals_i(a, o) __pz_equals_i(b, a, o, 0)
int __pz_equals_i(void *b, Id a, Id o, int quick = 1) {
  if (PZ_TYPE(a) == PZ_TYPE_STRING && PZ_TYPE(o) == PZ_TYPE_STRING) {
     PZ_ACQUIRE_STR_D(da, a, 0); PZ_ACQUIRE_STR_D(db, o, 0); 
     if (da.l != db.l) return 0;
     pz_string_size_t i;
     for (i = 0; i < da.l; i++) {
        if (da.s[i] != db.s[i]) return 0; }
     return 1;
  } 
  if ((PZ_TYPE(a) == PZ_TYPE_ARRAY && 
      PZ_TYPE(o) == PZ_TYPE_ARRAY) &&
      pz_ary_len(b, a) == pz_ary_len(b, o))  {
    if (quick && pz_ary_len(b, a) > 2) return 0;
    return pz_ary_equals_i(b, a, o);
  }
  int r= cnil2(b, a) == cnil2(b, o);
  return r;
}

Id pz_to_symbol(Id va_s) {
  if (PZ_TYPE(va_s) == PZ_TYPE_SYMBOL) return va_s;
  if (PZ_TYPE(va_s) != PZ_TYPE_STRING) return pzNil;
  Id s = va_s;
  PZ_TYPE_SET(s, PZ_TYPE_SYMBOL);
  return s;
}

Id pz_to_string(Id va_s) {
  if (PZ_TYPE(va_s) == PZ_TYPE_STRING) return va_s;
  if (PZ_TYPE(va_s) != PZ_TYPE_SYMBOL) return pzNil;
  Id s = va_s;
  PZ_TYPE_SET(s, PZ_TYPE_STRING);
  return s;
}

/*
 * Pairs
 */

typedef struct pz_pair_t {
   Id va_first; 
   Id va_rest;
};

#define pz_pair_new(b, f, r) __pz_pair_new(__func__, __LINE__, b, f, r)
Id __pz_pair_new(WLB, Id va_first, Id va_rest) {
    Id va_pr; 
    PZ_ALLOC(va_pr, PZ_TYPE_PAIR); 
    pz_pair_t *p; PZ_TYPED_VA_TO_PTR(pz_pair_t, p, va_pr, PZ_TYPE_PAIR, pzNil);
    p->va_first = pz_retain2(va_pr, va_first);
    p->va_rest = pz_retain2(va_pr, va_rest);
    pz_register_var(va_pr, w, l);
    return va_pr; }

// iterate

typedef struct {
  int initialized;
  pz_pair_t *p;
} pz_pair_iterate_t;

int pz_pair_iterate(void *b, Id va_pr, pz_pair_iterate_t *pr, Id *v) {
  pz_pair_t *p; PZ_TYPED_VA_TO_PTR(pz_pair_t, p, va_pr, PZ_TYPE_PAIR, 0);
  if (!pr->initialized) { 
      pr->p = p; 
      pr->initialized = 1; 
  } else {
    if (!pr->p->va_rest) return 0;
    Id va = pr->p->va_rest;
    pz_pair_t *pn; PZ_TYPED_VA_TO_PTR(pz_pair_t, pn, va, PZ_TYPE_PAIR, 0);
    pr->p = pn;
  }
  *v  = pr->p->va_first;
  return 1;
}

size_t pz_pair_length(void *b, Id va_pr) {
  pz_pair_iterate_t i;
  i.initialized = 0;
  Id v;
  size_t s = 0;
  while (pz_pair_iterate(b, va_pr, &i, &v)) s++;
  return s;
}

int pz_pair_free(void *b, Id va_pr) {
  pz_pair_t  *p; PZ_TYPED_VA_TO_PTR(pz_pair_t, p, va_pr, PZ_TYPE_PAIR, pzNil);
  pz_release(p->va_rest);
  pz_release(p->va_first);
  return 1;
}

/*
 * Hashtable
 */

typedef struct {
  Id va_key;
  Id va_value;
  Id va_next;
} pz_ht_entry_t;
#define PZ_HT_BUCKETS int((1000 - (2 * sizeof(Id))) / sizeof(Id))
typedef struct {
  int size;
  Id va_buckets[PZ_HT_BUCKETS];
  Id va_parent;
} pz_hash_t;

#define pz_ht_new(b) __pz_ht_new(__func__, __LINE__, b)
Id __pz_ht_new(WLB) {
    Id va_ht; 
    PZ_ALLOC(va_ht, PZ_TYPE_HASH); 
    //pz_lock_va(va_ht);
    pz_zero(b, va_ht, sizeof(pz_hash_t)); 
    //pz_unlock_va(va_ht);
    pz_register_var(va_ht, w, l);
    return va_ht; }

size_t pz_ht_hash(void *b, Id va_s) {
    return pz_hash_var(b, va_s) % PZ_HT_BUCKETS; }

pz_ht_entry_t pz_ht_null_node = { 0, 0, 0 };

#define PZ_HT_ITER_BEGIN(r) \
  Id va_hr; pz_ht_entry_t *hr = &pz_ht_null_node; \
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR2(pz_hash_t, ht, va_ht, PZ_TYPE_HASH, (r)); \
  size_t k = pz_ht_hash(b, va_key); \
  for (va_hr = ht->va_buckets[k];  \
      va_hr != 0 && hr != NULL; ) { \
    PZ_TYPED_VA_TO_PTR2(pz_ht_entry_t, hr, va_hr, PZ_TYPE_HASH_PAIR, (r)); \
    if (!hr || !pz_eq_i(va_key, hr->va_key)) goto next; 

#define PZ_HT_ITER_END(v) } return (v);

#define pz_ht_lookup(b, hr, ht, key, ef)  __pz_ht_lookup(w, l, b, hr, ht, key, ef)
int __pz_ht_lookup(WLB, pz_ht_entry_t **_hr, Id va_ht, Id va_key, int *exists_flag) {
  (*_hr) = &pz_ht_null_node; 
  if (exists_flag) *exists_flag = 0;
  PZ_HT_ITER_BEGIN(0) 
    if (exists_flag) *exists_flag = 1;
    (*_hr) = hr;
    return 1;
    next: va_hr = hr->va_next;
  PZ_HT_ITER_END(0);
}

#define pz_ht_delete(b, ht, key)  __pz_ht_delete(__func__, __LINE__, b, ht, key)
Id __pz_ht_delete(WLB, Id va_ht, Id va_key) {
  Id va_p = pzNil;
  pz_ht_entry_t *p = 0;
  PZ_HT_ITER_BEGIN(pzNil);
    p = (pz_ht_entry_t *)VA_TO_PTR(va_p);
    if (p) { p->va_next = hr->va_next; }
    else { ht->va_buckets[k] = pzNil; }
    pz_release(hr->va_value); pz_release(hr->va_key); pz_release(va_hr);
    ht->size -= 1;
    return pzTrue; 
  next: va_p = va_hr;
  PZ_HT_ITER_END(pzTrue);
}

int __pz_ht_free(void *b, Id va_ht) {
  int k; Id va_hr, va_p = pzNil; pz_ht_entry_t *hr = &pz_ht_null_node; 
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(pz_hash_t, ht, va_ht, PZ_TYPE_HASH, 0); 
  for (k = 0; k < PZ_HT_BUCKETS; k++) {
    for (va_hr = ht->va_buckets[k]; va_hr != 0 && hr != NULL; va_hr = hr->va_next) {
      PZ_TYPED_VA_TO_PTR(pz_ht_entry_t, hr, va_hr, PZ_TYPE_HASH_PAIR, 0); 
      pz_release(hr->va_value); pz_release(hr->va_key); 
      if (va_p) pz_release(va_p);
      va_p = va_hr;
    }
  }
  if (va_p) pz_release(va_p);
  pz_free(b, va_ht);
  return 1;
}
int pz_ht_free(void *b, Id va_ht) { 
    pz_lock_va(va_ht); int r = __pz_ht_free(b, va_ht);
    pz_unlock_va(va_ht); return r ;}

#define pz_ary_new(b) __pz_ary_new(__func__, __LINE__, b)
Id __pz_ary_new(WLB);
#define pz_ary_push(b, var_ary, va) \
  __pz_ary_push(__func__, __LINE__, b, var_ary, va)
Id __pz_ary_push(WLB, Id va_ary, Id va);


typedef struct {
  int initialized;
  int k;
  pz_hash_t *ht;
  Id va_hr;
  pz_ht_entry_t *hr;
} pz_ht_iterate_t;

pz_ht_entry_t *pz_ht_iterate(void *b, Id va_ht, pz_ht_iterate_t *h) {
  int new_bucket = 0;
  if (!h->initialized) {
    h->k = 0;
    h->hr = &pz_ht_null_node;
    h->va_hr = pzNil;
    PZ_TYPED_VA_TO_PTR(pz_hash_t, h->ht, va_ht, PZ_TYPE_HASH, 0); 
    h->initialized = 1;
  }
next_bucket:
  if (h->k >= PZ_HT_BUCKETS) return 0;
  if (!h->va_hr) { h->va_hr = h->ht->va_buckets[h->k];  new_bucket = 1;}
  if (!h->va_hr) { h->k++; goto next_bucket; }
  if (new_bucket) goto return_hr;
next_pair:
  h->va_hr = h->hr->va_next; 
  if (!h->va_hr) { h->k++; goto next_bucket; }
return_hr:
  PZ_TYPED_VA_TO_PTR(pz_ht_entry_t, h->hr, h->va_hr, PZ_TYPE_HASH_PAIR, 0); 
  if (!h->hr) goto next_pair;
  return h->hr;
}

#define pz_ht_get(b, ht, key) __pz_ht_get(__func__, __LINE__, b, ht, key)
#define pz_ht_get_exists(b, ht, key, ef) \
    __pz_ht_get(__func__, __LINE__, b, ht, key, ef)
Id __pz_ht_get(WLB, Id va_ht, Id va_key, int *exists_flag = 0x0) { 
  pz_ht_entry_t *hr; 
  pz_ht_lookup(b, &hr, va_ht, va_key, exists_flag);  P_0_R(hr, pzNil);
  return hr->va_value;
}

int pz_ht_size(void *b, Id va_ht) { 
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(pz_hash_t, ht, va_ht, PZ_TYPE_HASH, 0);
  return ht->size;
}

#define pz_ht_set(b, va_ht, va_key, va_value) \
  __pz_ht_set(__func__, __LINE__, b, va_ht, va_key, va_value)
Id __pz_ht_set(WLB, Id va_ht, Id va_key, Id va_value) {
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(pz_hash_t, ht, va_ht, PZ_TYPE_HASH, pzNil);
  int exists = 0;
  pz_ht_entry_t *hr; pz_ht_lookup(b, &hr, va_ht, va_key, &exists);
  size_t v = 0;
  Id va_hr = 0;
  pz_retain2(va_hr, va_value);

  if (!exists) { 
    v = pz_ht_hash(b, va_key);
    PZ_ALLOC(va_hr, PZ_TYPE_HASH_PAIR);
    pz_retain2(va_ht, va_hr); 
    hr = (pz_ht_entry_t *)VA_TO_PTR(va_hr); P_0_R(hr, pzNil);
    hr->va_key = pz_retain2(va_hr, va_key);
    ht->size += 1;
    pz_register_var(va_hr, w, l);
  } else {
    pz_release(hr->va_value);
  }

  hr->va_value = va_value;

  if (!exists) {
    hr->va_next = ht->va_buckets[v];
    ht->va_buckets[v] = va_hr;
  }
  return va_value;
}

#define pz_intern(s) __pz_intern(b, s)
Id __pz_intern(void *b, Id va_s) { 
  RetainGuard0(va_s);
  Id dict = PZ_TYPE(va_s) == PZ_TYPE_SYMBOL ? 
      pz_symbol_interns : pz_string_interns;
  Id sv = va_s; 
  PZ_TYPE_SET(sv, PZ_TYPE_STRING);
  Id va = pz_ht_get(b, dict, sv); 
  if (va) { return va; }
  if (cnil(pz_ht_set(b, dict, sv, va_s))) return pzNil;
  return pz_ht_get(b, dict, sv); 
}


Id pz_intern_cp(void *b, const char *sp, int to_symbol = 0) {
  Id s0 = S(sp);
  Id s = pz_retain0( to_symbol ? pz_to_symbol(s0) : s0);
  Id r = pz_intern(s);
  pz_release(s);  
  return r;
}

int pz_is_interned(void *b, Id va_s) {
  Id dict = PZ_TYPE(va_s) == PZ_TYPE_SYMBOL ? 
      pz_symbol_interns : pz_string_interns;
  Id sv = va_s; PZ_TYPE_SET(sv, PZ_TYPE_STRING);
  return pz_ht_get(b, dict, sv) != 0; 
}

#define pz_env_new(b, parent) __pz_env_new(__func__, __LINE__, b, parent)
Id __pz_env_new(WLB, Id va_ht_parent) {
  Id va = __pz_ht_new(w, l, b);
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(pz_hash_t, ht, va, PZ_TYPE_HASH, pzNil);
  ht->va_parent = va_ht_parent;
  return va;
}

#define PZ_ENV_FIND \
  Id va0 = va_ht, found_value = pzNil; \
  va0 = va0; \
  int found = 0; \
  do { \
    if (va_ht) { \
      found_value = __pz_ht_get(w, l, b, va_ht, va_key, &found); \
      if (!found) {  \
          pz_hash_t *ht; \
          PZ_TYPED_VA_TO_PTR2(pz_hash_t, ht, va_ht, PZ_TYPE_HASH, pzNil); \
          va_ht = ht->va_parent; \
      }\
    } \
  } while (va_ht && !found) 


#define pz_env_find(b, ht, key) __pz_env_find(__func__, __LINE__, b, ht, key)
Id __pz_env_find(WLB, Id va_ht, Id va_key) { 
  PZ_ENV_FIND; 
  return found_value; 
}

#define pz_env_find_and_set(b, ht, k, v) \
    __pz_env_find_and_set(__func__, __LINE__, b, ht, k, v)
Id __pz_env_find_and_set(WLB, Id va_ht, Id va_key, Id va_value) { 
  PZ_ENV_FIND;
  if (found) return pz_ht_set(b, va_ht, va_key, va_value); 
  else { return pz_ht_set(b, va0, va_key, va_value); }
}

void pz_add_globals(void *b, Id env);

void pz_setup() {
  if (sizeof(size_t) != 8) {
    printf("size_t must be 8 bytes in size!\n");
    exit(1);
  }
  PZ_TYPE_SET(pzTrue, PZ_TYPE_BOOL);
  PZ_LONG_SET(pzTrue, 1);
  PZ_TYPE_SET(pzTail, PZ_TYPE_SPECIAL);
  PZ_LONG_SET(pzTail, 1);
  PZ_TYPE_SET(pzError, PZ_TYPE_SPECIAL);
  PZ_LONG_SET(pzError, 2);
  pid = getpid();
}

char *cmd;

const char *pz_cmd_display() { return pz_perf_mode ? "perf" : "ponzi"; }

void *pz_init(void *b, size_t size) {
#ifdef PZ_GC_DEBUG
  memset(&pz_var_status, 0, sizeof(pz_var_status));
#endif
  if (!b) return 0;
  int r = pz_init_memory(b, size);
  if (r == 2) return 0;
  if (r) pz_add_globals(b, pz_globals);
  if (pz_interactive) 
      printf("%s %s started; %d vars available\n", pz_cmd_display(), 
          PZ_VERSION, pz_vars_free(b));
  return b;
}

/*
 * FFI
 */


typedef struct {
  Id filename;
  int line_number;
  int interactive;
} pz_parse_t;

#ifdef NEW
#define PZ_MAX_STACK 2000

struct pz_stack_frame_t {
  Id func_name;
  Id env;
  Id x;
  int last;
};

struct pz_interp_t {
  pz_parse_t *ps;
  size_t nested_depth;
  int stack_overflow;
  int in_compilation;
  pz_stack_frame_t frames[2000];
};

#else

struct pz_interp_t {
  pz_parse_t *ps;
  Id _this;
  Id _prev;
  Id _env;
  Id _x;
  size_t nested_depth;
  int stack_overflow;
  int last;
  pz_interp_t *previous_ip;
};

#endif


#ifdef NEW
typedef struct { Id (*func_ptr)(void *b, Id, pz_interp_t *, 
    pz_stack_frame_t *sf); Id name; } pz_cfunc_t;
#else
typedef struct { Id (*func_ptr)(void *b, Id, pz_interp_t *); Id name; } 
    pz_cfunc_t;
#endif

#define pz_define_func(b, n, p, e) \
    __pz_define_func(__func__, __LINE__, b, n, p, e)
Id __pz_define_func(WLB, 
#ifdef NEW
    const char *name, Id (*p)(void *, Id, pz_interp_t *, 
    pz_stack_frame_t *sf), Id env
#else
    const char *name, Id (*p)(void *, Id, pz_interp_t *), Id env
#endif
  ) {
  Id va_f; PZ_ALLOC(va_f, PZ_TYPE_CFUNC);
  pz_cfunc_t *cf; PZ_TYPED_VA_TO_PTR0(pz_cfunc_t, cf, va_f, PZ_TYPE_CFUNC, pzNil);
  cf->func_ptr = p;
  cf->name = pz_intern(pz_to_symbol(S(name)));
  pz_ht_set(b, env, cf->name, va_f);
  pz_register_var(va_f, w, l);
  return pzTrue;
}

Id pz_cfunc_to_bin_adr_s(void *b, Id va_f) { 
  pz_cfunc_t *cf; PZ_TYPED_VA_TO_PTR(pz_cfunc_t, cf, va_f, PZ_TYPE_CFUNC, pzNil);
  size_t adr = (size_t)cf->func_ptr;
  return pz_string_new(b, (const char *)&adr, sizeof(size_t));
}

Id pz_va_to_bin_adr_s(void *b, Id va) { 
  size_t adr = PZ_ADR(va);
  return pz_string_new(b, (const char *)&adr, sizeof(size_t));
}

#ifdef NEW
Id pz_call(void *b, Id va_f, Id x, pz_interp_t *pi, pz_stack_frame_t *sf) { 
#else
Id pz_call(void *b, Id va_f, Id x, pz_interp_t *pi) { 
#endif
  pz_cfunc_t *cf; PZ_TYPED_VA_TO_PTR(pz_cfunc_t, cf, va_f, PZ_TYPE_CFUNC, 
      pzNil);
#ifdef NEW
  Id r = cf->func_ptr(b, x, pi, sf);
#else
  Id r = cf->func_ptr(b, x, pi);
#endif
  return r;
}

/*
 * Array
 */

#define PZ_ARY_MAX_ENTRIES int((PZ_CELL_SIZE - (sizeof(int) * 5)) / sizeof(Id))
typedef struct {
  int size;
  int start; 
  int lambda;
  int macro;
  int line_number;
  Id va_entries[PZ_ARY_MAX_ENTRIES];
} pz_array_t;

Id __pz_ary_new(WLB) {
  Id va_ary; PZ_ALLOC(va_ary, PZ_TYPE_ARRAY); 
  pz_register_var(va_ary, w, l);
  pz_zero(b, va_ary, 0); return va_ary; 
}

void __ary_retain_all(void *b, Id from, pz_array_t *a) {
  int i = 0; 
  for (i = a->start; i < a->size; i++) pz_retain(from, a->va_entries[i]);
}

#define pz_ary_clone(b, va_s) \
    __pz_ary_clone(__func__, __LINE__, b, va_s, -1, -1)
#define pz_ary_clone_part(b, va_s, s, c) \
    __pz_ary_clone(__func__, __LINE__, b, va_s, s, c)
Id __pz_ary_clone(WLB, Id va_s, int start, int count) {
  pz_array_t *ary_s; 
  PZ_TYPED_VA_TO_PTR(pz_array_t, ary_s, va_s, PZ_TYPE_ARRAY, pzNil);
  Id va_c; PZ_ALLOC(va_c, PZ_TYPE_ARRAY); pz_zero(b, va_c, 0); 
  char *p_c = VA_TO_PTR(va_c), *p_s = VA_TO_PTR(va_s);
  memcpy(p_c, p_s, PZ_CELL_SIZE);
  pz_array_t *a = (pz_array_t *)p_c;
  int c = a->size - a->start;
  if (start < 0) start = 0;
  if (count < 0) count = c + count + 1;
  if (start + count > a->size) count = a->size - start;
  a->start = start;
  a->size = start + count;
  __ary_retain_all(b, va_c, a);
  pz_register_var(va_c, w, l);
  return va_c;
}

int pz_ary_free(void *b, Id va_ary) {
  pz_array_t *ary; PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, 0);
  int i = 0;
  for (i = ary->start; i < ary->size; i++) pz_release(ary->va_entries[i]);
  pz_free(b, va_ary);
  return 1;
}

#define pz_ary_new_join(b, a, o) \
  __pz_ary_new_join(__func__, __LINE__, b, a, o)
Id __pz_ary_new_join(WLB, Id a, Id o) {
  pz_array_t *aa; PZ_TYPED_VA_TO_PTR(pz_array_t, aa, a, PZ_TYPE_ARRAY, pzNil);
  pz_array_t *ab; PZ_TYPED_VA_TO_PTR(pz_array_t, ab, o, PZ_TYPE_ARRAY, pzNil);
  Id n; PZ_ALLOC(n, PZ_TYPE_ARRAY); pz_zero(b, n, 0); 
  pz_array_t *an; PZ_TYPED_VA_TO_PTR(pz_array_t, an, n, PZ_TYPE_ARRAY, pzNil);
  int aas = aa->size - aa->start;
  an->size = aas + ab->size - ab->start;
  PZ_CHECK_ERROR((an->size >= PZ_ARY_MAX_ENTRIES), "array is full", pzNil);
  memcpy(&an->va_entries, &aa->va_entries[aa->start], aas * sizeof(Id));
  memcpy(&an->va_entries[aas], &ab->va_entries[ab->start], 
      (ab->size - ab->start) * sizeof(Id));
  __ary_retain_all(b, n, an);
  pz_register_var(n, w, l);
  return n;
}

#define pz_ary_join_by_s(b, a, j) \
    __pz_ary_join_by_s(__func__, __LINE__, b, a, j)
Id ___pz_ary_join_by_s(WLB, Id va_ary, Id va_js) {
  pz_array_t *ary; 
  PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  PZ_ACQUIRE_STR_D(djs, va_js, pzNil);
  char rs[PZ_CELL_SIZE];
  pz_string_size_t ts = 0;
  int i;
  for (i = ary->start; i < ary->size; i++) {
    Id va_s = ary->va_entries[i];
    PZ_ACQUIRE_STR_D(ds, va_s, pzNil);
    PZ_CHECK_ERROR((ts + ds.l + djs.l >= PZ_CELL_SIZE),"join: array too large",pzNil);
    memcpy(rs + ts, ds.s, ds.l);
    ts += ds.l;
    memcpy(rs + ts, djs.s, djs.l);
    ts += djs.l;
  }
  Id va_n = __pz_string_new(w, l, b, rs, ts ? ts - djs.l : ts);
  return va_n;
}

Id __pz_ary_join_by_s(WLB, Id va_ary, Id va_js) {
  pz_retain0(va_ary); pz_retain0(va_js);
  Id r = ___pz_ary_join_by_s(w, l, b, va_ary, va_js);
  pz_release(va_ary); pz_release(va_js);
  return r;
}

Id __pz_ary_push(WLB, Id va_ary, Id va) {
  pz_array_t *ary; 
  PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  PZ_CHECK_ERROR((ary->size >= PZ_ARY_MAX_ENTRIES), "array is full", pzNil);
  ary->size += 1;
  ary->va_entries[ary->start + ary->size - 1] = pz_retain2(va_ary, va);
  return va_ary;
}

int pz_ary_set_lambda(void *b, Id va_ary) {
  pz_array_t *ary; PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, 0);
  ary->lambda = 1;
  return 1;
}

int pz_ary_is_lambda(void *b, Id va_ary) {
  pz_array_t *ary; PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, 0);
  return ary->lambda;
}

int pz_ary_set_macro(void *b, Id va_ary) {
  pz_array_t *ary; PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, 0);
  ary->macro = 1;
  return 1;
}

int pz_ary_is_macro(void *b, Id va_ary) {
  pz_array_t *ary; PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, 0);
  return ary->macro;
}

int pz_ary_set_line_number(void *b, Id va_ary, int line_number) {
  pz_array_t *ary; PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, 0);
  ary->line_number = line_number;
  return 1;
}

int pz_ary_get_line_number(void *b, Id va_ary) {
  pz_array_t *ary; PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, 0);
  return ary->line_number;
}

Id pz_ary_map(void *b, Id va_ary, Id (*func_ptr)(void *b, Id)) {
  pz_array_t *ary; 
  PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  int i;
  Id r = pz_ary_new(b);
  for (i = ary->start; i < ary->size; i++) 
      pz_ary_push(b, r, func_ptr(b, ary->va_entries[i]));
  return r;
}

Id pz_ary_shift(void *b, Id va_ary) {
  pz_array_t *ary; 
  PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  if (ary->size - ary->start <= 0) { return pzNil; } 
  ary->start++;
  return pz_release_no_delete(ary->va_entries[ary->start - 1]);
}

Id pz_ary_set(void *b, Id va_ary, int i, Id va) {
  pz_array_t *ary; 
  PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  PZ_CHECK_ERROR((ary->start + i >= PZ_ARY_MAX_ENTRIES), 
      "array index too large", pzNil);
  pz_retain(va_ary, va);
  if ((i + 1) - ary->start > ary->size) {
     int ns = i + 1 - ary->start;
     int i;
     for (i = ary->size + ary->start; i < ns + ary->start; i++) {
       ary->va_entries[i] = 0x0;
     }
     ary->size = ns;
  }
  Id va_o = ary->va_entries[ary->start + i];
  if (va_o) pz_release(va_o); 
  ary->va_entries[ary->start + i] = va;
  return va;
}

Id pz_ary_pop(void *b, Id va_ary) {
  pz_array_t *ary; 
  PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  if (ary->size - ary->start <= 0) { return pzNil; } 
  ary->size--;
  return pz_release_no_delete(ary->va_entries[ary->start + ary->size]);
}

#define pz_ary_len(b, a) __pz_ary_len(__func__, __LINE__, b, a)
int __pz_ary_len(WLB, Id va_ary) {
  pz_array_t *ary; PZ_TYPED_VA_TO_PTR2(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, -1);
  return ary->size - ary->start;
}

Id pz_ary_index(void *b, Id va_ary, int i) {
  pz_array_t *ary; 
  PZ_TYPED_VA_TO_PTR(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  if (i < 0) i = ary->size - ary->start + i;
  if (ary->size - ary->start <= i) { return pzNil; } 
  return ary->va_entries[ary->start + i];
}

Id ca_i(void *b, Id va_ary, int i) { return pz_ary_index(b, va_ary, i); }
#define lambda_vdecl(ary) ca_f(ary)
#define lambda_body(ary) ca_s(ary)
#define lambda_env_ctx(ary) ca_th(ary)
#define ca_f(ary) ca_i(b, ary, 0)
#define ca_s(ary) ca_i(b, ary, 1)
#define ca_th(ary) ca_i(b, ary, 2)
#define ca_fth(ary) ca_i(b, ary, 3)

#define pz_ary_iterate(b, va_ary, i, r) \
  __pz_ary_iterate(__func__, __LINE__, b, va_ary, i, r)
Id __pz_ary_iterate(WLB, Id va_ary, int *i, Id *r) {
  pz_array_t *ary; 
  PZ_TYPED_VA_TO_PTR2(pz_array_t, ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  if (*i >= ary->size - ary->start) { return pzNil; }
  *r = pz_ary_index(b, va_ary, (*i)++); 
  return pzTrue;
}

int pz_ary_contains_only_type_i(void *b, Id a, int t) {
  int i = 0; Id va;
  while (pz_ary_iterate(b, a, &i, &va))
      if (!pz_is_type_i(va, t))  return 0;
  return 1;
}

int pz_ary_equals_i(void *b, Id a, Id o) {
  int ai = 0, oi = 0; 
  Id va1, va2, m1, m2;
  if (pz_ary_len(b, a) != pz_ary_len(b, o)) return 0;
  if (pz_ary_len(b, a) == 0) return 1;
  int matches = 0 ;

  do {
    m1 = pz_ary_iterate(b, a, &ai, &va1);
    m2 = pz_ary_iterate(b, o, &oi, &va2);
    matches = va1 == va2;
  } while (matches && m1);
  return matches;
}

#define PZ_PUSH_STRING { \
    int len = ds.s + i - last_start - match_pos; \
    Id va_ns = __pz_string_new(w, l, b, last_start, len); VA_0_R(va_ns, pzNil); \
    if (!pz_ary_push(b, va_ary, va_ns)) return pzNil; }

#define pz_string_split(b, s, sep) \
    __pz_string_split(__func__, __LINE__, b, s, sep)
Id __pz_string_split(WLB, Id va_s, char sep) {
  RetainGuard0(va_s);
  PZ_ACQUIRE_STR_D(ds, va_s, pzNil);
  if (ds.l == 0) return pzNil;
  Id va_ary = __pz_ary_new(w, l, b);
  int i, match_pos = 0;
  char *last_start = ds.s;

  for (i = 0; i < ds.l; i++) {
    if (ds.s[i] != sep) {
      if (match_pos > 0) {
        PZ_PUSH_STRING;
        last_start = ds.s + i;
        match_pos = 0;
      }
      continue;
    }
    match_pos++;
  }
  PZ_PUSH_STRING;
  return va_ary;
}

#define pz_string_split2(b, s, sep) \
    __pz_string_split2(__func__, __LINE__, b, s, sep)
Id __pz_string_split2(WLB, Id va_s, Id sep) {
  PZ_ACQUIRE_STR_D(ds, sep, pzNil);
  if (ds.l == 0) return pzNil;
  return __pz_string_split(w, l, b, va_s, ds.s[0]);
}

/*
 * regular expressions
 *
 * Implementation heavily borrows from Rob Pike's regexp implementation,
 * as described here:
 *
 * http://www.cs.princeton.edu/courses/archive/spr09/cos333/beautiful.html
 */

typedef struct {
  Id match_s;
} pz_rx_t;

#define pz_rx_new(match_s) __pz_rx_new(__func__, __LINE__, b, match_s);
Id __pz_rx_new(WLB, Id match_s) {
  Id va_rx; PZ_ALLOC(va_rx, PZ_TYPE_REGEXP); 
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(pz_rx_t, rx, va_rx, PZ_TYPE_REGEXP, pzNil);
  pz_zero(b, va_rx, 0);
  rx->match_s = pz_retain2(va_rx, match_s);
  pz_register_var(va_rx, w, l);
  return va_rx; 
}

int pz_rx_free(void *b, Id va_rx) {
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(pz_rx_t, rx, va_rx, PZ_TYPE_REGEXP, 0);
  pz_release(rx->match_s);
  return 1;
}

Id pz_rx_match_string(void *b, Id va_rx) {
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(pz_rx_t, rx, va_rx, PZ_TYPE_REGEXP, pzNil);
  return rx->match_s;
}

int __pz_rx_matchhere(char *ms, int ml, char *s, int sl);

int __pz_rx_matchstar(int c, char *ms, int ml, char *s, int sl) {
  do {
    if (__pz_rx_matchhere(ms, ml, s, sl)) return 1;
    if (sl < 1) return 0;
    if (c != '.' && (sl < 1 || s[0] != c)) return 0;
    sl--;
    s++;
  } while (1);
}

int __pz_rx_matchhere(char *ms, int ml, char *s, int sl) {
  if (ml < 1) return 1;
  if (ml > 1 && ms[1] == '*')
    return __pz_rx_matchstar(ms[0], ms + 2, ml - 2, s, sl);
  if (ms[0] == '$' && ml == 1)
    return sl == 0;   
  if (sl > 0 && (ms[0] == '.' || ms[0] == s[0])) 
    return __pz_rx_matchhere(ms + 1, ml - 1, s + 1, sl - 1);
  return 0;
}

int pz_rx_match(void *b, Id va_rx, Id va_s) {
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(pz_rx_t, rx, va_rx, PZ_TYPE_REGEXP, 0);
  PZ_ACQUIRE_STR_D(ms, rx->match_s, 0);
  PZ_ACQUIRE_STR_D(s, va_s, 0);
  if (!ms.l) return 0;
  if (ms.s[0] == '^')
      return __pz_rx_matchhere(ms.s + 1, ms.l - 1, s.s, s.l);
  do {
    if (__pz_rx_matchhere(ms.s, ms.l, s.s, s.l)) return 1;
    s.s++;
    s.l--;
  } while (s.l > 0);
  return 0;
}

/*
 * Dump
 */

int pz_dump_to_d(void *b, Id va, pz_str_d *d);

uchar pz_dump_status[PZ_VAR_COUNT / 8];

#define PZ_ONLY_REFER_TYPES(v) \
  PZ_NO_BASIC_TYPES(v, v); \
  int t = PZ_TYPE(va); \
  if (!(t == PZ_TYPE_HASH || t == PZ_TYPE_ARRAY || t == PZ_TYPE_PAIR || \
      t == PZ_TYPE_HASH_PAIR)) return v;

  

int pz_dump_have_va_p(Id va) {
  PZ_ONLY_REFER_TYPES(0);
  size_t adr = PZ_ADR(va);
  uchar b = pz_dump_status[adr >> 3];
  return (b & (1 << (adr % 8))) > 0;
}

int pz_dump_mark_va(Id va) {
  PZ_ONLY_REFER_TYPES(0);
  size_t adr = PZ_ADR(va);
  size_t i = adr >> 3;
  uchar b = pz_dump_status[i];
  pz_dump_status[i] = b | (1 << (adr % 8));
  return 1;
}


#define pz_strncat_0(d, s) if (!__pz_strncat_0(d, s)) return 0;
#define pz_strncat(d, s, l) if (!__pz_strncat(d, s, l)) return 0;

int __pz_strncat(pz_str_d *d, const char *s, size_t sl) {
  size_t l = d->l + sl;
  PZ_CHECK_ERROR((l + 1 > 16384), "pz_strncat: string too large", 0);
  memcpy(d->s + d->l, s, sl);
  d->l += sl;
  *(d->s + d->l) = 0x0;
  return 1;
}

int __pz_strncat_0(pz_str_d *d, const char *s) { return __pz_strncat(d, s, strlen(s)); }

#define pz_append_format(d, format, values...) \
  { char bs[1024]; snprintf(bs, 1023, format, values); \
  pz_strncat_0(d, bs); }

int pz_dump_va(void *b, Id va, pz_str_d *d) {
  if (pz_dump_have_va_p(va)) {
    pz_strncat_0(d, " ... ");
    return 0;
  }
  pz_dump_mark_va(va);
  if (d->dump_recurse) {
    pz_dump_to_d(b, va, d);
    return 1;
  } else {
    pz_append_format(d, "#x%x", PZ_ADR(va));
    return 0;
  }
  return 0;
}

int pz_ary_dump(void *b, Id a, pz_str_d *d) {
  int i = 0; Id va;
  int first = 1;
  int l = pz_ary_len(b, a);
  if (pz_ary_is_lambda(b, a)) {
    pz_strncat_0(d, "(lambda ");
    Id vdecl = ca_f(a);
    pz_dump_to_d(b, vdecl, d);
    pz_strncat_0(d, " ");
    pz_dump_to_d(b, ca_s(a), d);
    pz_strncat_0(d, ")");
    return 1;
  }
  if (d->dump_debug) pz_append_format(d, "%d:", l);


  pz_strncat_0(d, "#(");
  while (pz_ary_iterate(b, a, &i, &va)) {
    if (!first) { pz_strncat_0(d, " "); }
    pz_dump_va(b, va, d);
    first = 0;
  }
  pz_strncat_0(d, ")");
  return 1;
}

int pz_pair_dump(void *b, Id p, pz_str_d *d) {
  pz_strncat_0(d, "( ");
  pz_pair_iterate_t i;
  i.initialized = 0;
  Id va;
  int first = 1;
  while (pz_pair_iterate(b, p, &i, &va)) {
    if (!first) { pz_strncat_0(d, " "); }
    pz_dump_va(b, va, d);
    first = 0;
  }
  pz_strncat_0(d, ")");
  return 1;
}

int pz_append_quoted_string(void *b, Id s, pz_str_d *d) {
  PZ_ACQUIRE_STR_D(dt, s, 0);
  char r[16384];
  int i, ri; 
  for (ri = i = 0; i < dt.l && ri < 16300; i++, ri++) {
    uchar c = dt.s[i];
    if (c < 0x20 || c > 0x80) {
      if (c == '\n' || c == '\r') {
        r[ri++] = '\\'; r[ri] = c == '\n' ? 'n' : 'r';
      } else {
        snprintf(r + ri, 5, "\\x%02x", c);
        ri += 3;
      }
    } else r[ri] = dt.s[i];
  }
  r[ri] = 0x0;
  pz_append_format(d, "\"%s\"", (const char *)&r);
  return 1;
}

int pz_string_dump(void *b, Id s, pz_str_d *d) {
  if (PZ_TYPE(s) == PZ_TYPE_SYMBOL) {
    pz_append_format(d, "%s%s", 
        (d->dump_inspect || d->dump_debug) ? "'" : "", pz_string_ptr(s));
    return 1;
  }
  if (d->dump_inspect || d->dump_debug) 
      return pz_append_quoted_string(b, s, d);
  PZ_ACQUIRE_STR_D(dt, s, 0);
  pz_strncat(d, dt.s, dt.l);
  return 1;
}

int __pz_hash_pair_dump(void *b, pz_ht_entry_t *hr, pz_str_d *d) {
  pz_strncat_0(d, "(");
  pz_dump_va(b, hr->va_key, d);
  pz_strncat_0(d, " . ");
  pz_dump_va(b, hr->va_value, d);
  pz_strncat_0(d, ")");
  return 1;
}

int pz_hash_pair_dump(void *b, Id va, pz_str_d *d) {
  pz_ht_entry_t *hr;
  PZ_TYPED_VA_TO_PTR(pz_ht_entry_t, hr, va, PZ_TYPE_HASH_PAIR, 0); 
  return __pz_hash_pair_dump(b, hr, d);
}

int pz_ht_dump(void *b, Id va_ht, pz_str_d *d) {
  pz_ht_iterate_t h;
  h.initialized = 0;
  pz_ht_entry_t *hr;
  if (d->dump_debug) pz_append_format(d, "%d:", pz_ht_size(b, va_ht));

  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(pz_hash_t, ht, va_ht, PZ_TYPE_HASH, 0);
  if (d->dump_debug && ht->va_parent) 
      pz_append_format(d, "[parent:#x%x]", PZ_ADR(ht->va_parent));

  pz_strncat_0(d, "(#hash ");
  int first = 1;
  while ((hr = pz_ht_iterate(b, va_ht, &h))) {
    if (!first) { pz_strncat_0(d, " "); }
    __pz_hash_pair_dump(b, hr, d);
    first = 0;
  }
  pz_strncat_0(d, " )");
  return 1;
}

int pz_rx_dump(void *b, Id va_rx, pz_str_d *d) {
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(pz_rx_t, rx, va_rx, PZ_TYPE_REGEXP, 0);
  pz_append_format(d, "(#/ %s)", pz_string_ptr(rx->match_s));
  return 1;
}

int pz_char_dump(void *b, Id va_c, pz_str_d *d) {
  uchar c = PZ_CHAR(va_c);
  if (d->dump_debug) pz_strncat_0(d, "CHAR:");
  if (d->dump_debug || d->dump_inspect) {
    pz_strncat_0(d, "#\\");
    int detected = 1;
    switch (c) {
      case 0x20: pz_strncat_0(d, "space"); break;
      case '\n': pz_strncat_0(d, "newline"); break;
      case '\r': pz_strncat_0(d, "return"); break;
      default: detected = 0; break;
    }
    if (!detected) {
      if (c < 0x20 || c > 0x80) pz_append_format(d, "x%02x", c)
      else pz_append_format(d, "%c", c);
    }
  } else pz_append_format(d, "%c", c);
  return 1;
}

const char* pz_special_dump(Id va) {
  if (va == pzTail) return "#tail-recursion"; 
  if (va == pzError) return "#E!";
  return "<unknown>";
}

int __pz_dump_to_d(void *b, Id va, pz_str_d *d) {
  switch (PZ_TYPE(va)) {
    case PZ_TYPE_PAIR: return pz_pair_dump(b, va, d); break;
    case PZ_TYPE_ARRAY: return pz_ary_dump(b, va, d); break;
    case PZ_TYPE_HASH: return pz_ht_dump(b, va, d); break;
    case PZ_TYPE_HASH_PAIR: return pz_hash_pair_dump(b, va, d); break;
    case PZ_TYPE_REGEXP: return pz_rx_dump(b, va, d); break; 
    case PZ_TYPE_STRING: case PZ_TYPE_SYMBOL: 
        return pz_string_dump(b, va, d); break;
    case PZ_TYPE_CFUNC:
      { pz_cfunc_t *cf; PZ_TYPED_VA_TO_PTR(pz_cfunc_t, cf, va, PZ_TYPE_CFUNC, 0);
      if (d->dump_debug) pz_append_format(d, "cfunc:#x%lx", (long)&cf->func_ptr)
      else pz_append_format(d, "#<cfunc:%s>", pz_string_ptr(cf->name));
      return 1; break; }
    case PZ_TYPE_SPECIAL: {
        if (d->dump_debug) pz_append_format(d, "SPECIAL:#x%lx:", va);
        pz_strncat_0(d, pz_special_dump(va));
        return 1; break; }
    case PZ_TYPE_FLOAT: pz_append_format(d, "%f", PZ_FLOAT(va)); return 1; break;
    case PZ_TYPE_LONG: pz_append_format(d, "%ld", PZ_LONG(va)); return 1; break;
    case PZ_TYPE_CHAR: return pz_char_dump(b, va, d); break;
    case PZ_TYPE_BOOL: {
      if (d->dump_debug) pz_append_format(d, "BOOL:%lx:", va); 
      pz_strncat_0(d, va ? "#t" : "#f");
      return 1; break; }
  }
  return 0;
}

int pz_dump_to_d(void *b, Id va, pz_str_d *d) {
  if (d->dump_debug) 
      pz_append_format(d, "#x%x:%s<", PZ_ADR(va), pz_type_to_cp(PZ_TYPE(va)));
  int r = __pz_dump_to_d(b, va, d);
  if (d->dump_debug) pz_strncat_0(d, ">");
  return r;
}

int pz_dump_to_string(void *b, Id va, char *dsc, size_t *l, int flags) {
  *dsc = 0x0;
  pz_str_d d;
  d.s = dsc;
  d.l = 0;
  d.dump_recurse = (flags & PZ_DUMP_RECURSE) > 0;
  d.dump_inspect = (flags & PZ_DUMP_INSPECT) > 0;
  d.dump_debug = (flags & PZ_DUMP_DEBUG) > 0;
  memset(&pz_dump_status, 0, sizeof(pz_dump_status));
  pz_dump_to_d(b, va, &d);
  if (l) *l = d.l;
  return 1;
}

void pz_print_dump(void *b, Id va, int flags) {
  char dsc[16834];
  pz_dump_to_string(b, va, (char *)&dsc, 0, flags);
  printf("%s ", dsc);
}

int pz_register_string_constant(void *b, Id _s) {
  RG(sg);
  Id s = pz_intern(sg = _s);
  Id v;
  if ((v = pz_ht_get(b, pz_string_constants_dict, s))) return PZ_LONG(v);
  pz_ary_push(b, pz_string_constants, s);
  int i = pz_ary_len(b, pz_string_constants) - 1;
  pz_ht_set(b, pz_string_constants_dict, s, pz_long(i));
  return i;
}


Id pz_input(void *b, pz_interp_t *pi, FILE *f, const char *prompt) {
  if (pi->ps->interactive) printf("%ld:%s", pz_active_entries(b), prompt); 
  Id cs = IS("(begin");
  size_t ll; 
  char p[16384], *pp;
  int check_hashbang_first_line = !pi->ps->interactive;
next_line:
  pp = fgetln(f, &ll);
  size_t l = ll > 16383 ? 16383 : ll;
  memcpy(p, pp, l);
  p[l] = 0x0;
  if (l > 0 && check_hashbang_first_line && (p[0] == '#')) {
    check_hashbang_first_line = 0;
    pi->ps->line_number++;
    goto next_line;
  }
  char* pignore;
  if (l > 0 && (pignore = index(p, ';'))) l = pignore - p;
  check_hashbang_first_line = 0; 
  Id s = pz_string_new(b, p, l);
  if (!pi->ps->interactive) {
    if (feof(f)) { 
      pz_release_ja(s);
      pz_string_append(b, cs, IS(")"));
      return cs;
    }
    pz_retain0(s);
    pz_string_append(b, cs, s);
    pz_release(s);
    goto next_line;
  }
  return s;
}

unsigned long pz_current_time_ms() {
  struct timeval now; 
  gettimeofday(&now, NULL); 
  return now.tv_sec * 1000 + (now.tv_usec / 1000);
}

#ifdef NEW
#include "eval.cpp"
#else
#include "scheme-parser.cpp"
#endif

void pz_setup_perf() {
  void *b = pz_perf;
  pz_add_globals(b, pz_globals);
  FILE* fb = fopen("boot.scm", "r");
  pz_repl(b, fb, S("boot.scm"), 0);
}

void test_fuck() {
  void *b = pz_heap;
  Id a = S("STRING");
  printf("type: %d\n", PZ_TYPE(a));
  PZ_TYPE_SET(a, PZ_TYPE_SYMBOL);
  printf("type: %d\n", PZ_TYPE(a));
  PZ_TYPE_SET(a, PZ_TYPE_STRING);
  printf("type: %d\n", PZ_TYPE(a));
  exit(0);
}

} // end namespace

using namespace ponzi;

int main(int argc, char **argv) {
  pz_setup();
  pz_interactive = isatty(0);
  cmd = argv[0];
  // "perf.bin"
  pz_perf_mode = strlen(cmd) > 8 && 
      (strcmp(cmd + strlen(cmd) - 8, "perf.bin") == 0);
  const char *scm_filename = 0;
  if (argc > 1) { 
    scm_filename = argv[argc - 1];
    if (!pz_perf_mode || (pz_perf_mode && argc == 3)) {
      if ((fin = fopen(scm_filename, "r")) == NULL) {
          perror(argv[argc - 1]); exit(1); }
      pz_interactive = 0;
      pz_verbose = argc > 2;
    } else {
      fin = stdin;
    }
  } else { fin = stdin; }
  pz_heap = pz_init(pz_private_memory_create(), PZ_HEAP_SIZE);
  if (!pz_heap) exit(1);
  void *b = pz_heap;
  if (!scm_filename) scm_filename = "stdin.scm";
  Id fn = pz_string_append(b, S(scm_filename), S(".perf"));
  pz_perf_mc = pz_shared_memory_create(pz_string_ptr(
      pz_retain0(fn)), PZ_PERF_MEM_SIZE);
  if (pz_perf_mc) { pz_perf = pz_perf_mc->base;  }
  else { printf("failed to create perf segment!\n"); exit(1); }
  int r = pz_init_memory(pz_perf, PZ_PERF_MEM_SIZE);
  if (r == 2) exit(1);
  if (r) pz_setup_perf();
  pz_load(b, S("boot.scm"));
  //if (pz_perf_mode) test_perf();
  if (pz_perf_mode) b = pz_perf;
  debug = 1;
  // new_pz_repl(b, fin, S(scm_filename), pz_interactive);
  pz_repl(b, fin, S(scm_filename), pz_interactive);
  return 0;
}
