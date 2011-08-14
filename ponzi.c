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
#include <semaphore.h>
#include <signal.h>

#include "atomic.c"

#define PZ_MAX_INT_VALUE 0xffffffff


#define WL const char *w, int l
#define WLB const char *w, int l, void *b


#if 1
#define CDS(w, va) printf("%s %lx %x %s %s\n", w, (size_t)b, PZ_ADR(va), pz_type_to_cp(PZ_TYPE(va)), pz_string_ptr(va));
#define CDS2(w, va_h, va) printf("%s %lx %x %x %s %s\n", w, (size_t)b, PZ_ADR(va_h), PZ_ADR(va), pz_type_to_cp(PZ_TYPE(va)), pz_string_ptr(va));
#else
#define CDS(w, va) 
#define CDS2(w, va_h, va)
#endif

#define PZ_VERSION "0.0.1"
//#define PZ_GC_DEBUG  

int pid;

int debug = 0;

typedef union {
  float f;
  int i;
  int address;
} pz_reg_type;

typedef union { size_t s; struct { short int type; pz_reg_type d; } t; } Id;


#define PZ_DB_MAGIC 0xF0F0
#define PZ_DB_VERSION 3

#define PZ_ADR(va) va.t.d.address
#define PZ_TYPE(va) va.t.type
#define PZ_INT(va) va.t.d.i
#define PZ_FLOAT(va) va.t.d.f

static Id pzNil = {0}; 
static Id pzTrue = {0};
static Id pzFalse = {0};
static Id pzTail = {0};
static Id pzError = {0}; 
static Id pzHeader = {0}; 

/*
 * Forwards
 */

#define pz_string_ptr(s) __pz_string_ptr(__func__, __LINE__, b, s)
char *__pz_string_ptr(const char *w, int l, void *b, Id va_s);


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
    const char *error_msg, char *handle) {
  char h[1024];
  if (handle != 0)  { snprintf(h, 1023, " '%s'", handle); } 
  else { strcpy(h, ""); }
  snprintf((char *)&pz_error.error_str, 1023, "%s%s: %s", ctx, h, error_msg);
  printf("error: %s\n", pz_error.error_str);
  pz_error.error_number = errno;
  return pzError;
}

Id pz_handle_error(int check, const char *ctx, char *handle) {
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
typedef struct {
  const char *where;
  int line;
  int new;
  const char *retain_where;
  int retain_line;
  int retain_adr;
  size_t release_counter;
  size_t retain_counter;
} pz_var_status_t;

pz_var_status_t pz_var_status[PZ_VAR_COUNT];

void pz_register_var(Id va, WL) {
  int adr = PZ_ADR(va);
  pz_var_status[adr].where = w;
  pz_var_status[adr].line = l;
  pz_var_status[adr].new = 1;
}
#else
#define pz_register_var(va, where, line)
#endif

void *pz_private_memory_create() {
  void *base = 0;
  base = mmap(0, PZ_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 
      -1, (off_t)0);
  if (!pz_handle_error(base == MAP_FAILED, "mmap", 0).s) return 0;
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
  pz_shm_t *mc = calloc(1, sizeof(pz_shm_t));
  if (!mc) {
    pz_handle_error_with_err_string_nh( __func__, "Out of memory");
    return 0;
  }

  mc->filename = fn;
  mc->size = size;
  void *base = 0;
  if (!pz_handle_error((mc->fd = open(fn, O_RDWR, (mode_t)0777)) == -1, 
      "open", fn).s) goto open_failed;
  if (!pz_handle_error(lseek(mc->fd, mc->size - 1, SEEK_SET) == -1, 
      "lseek", fn).s) goto failed;
  if (!pz_handle_error(write(mc->fd, "", 1) != 1, "write", fn).s) goto failed;
  mc->base = mmap(0, mc->size, PROT_READ | PROT_WRITE, MAP_SHARED, mc->fd, 
      (off_t)0);
  if (!pz_handle_error(mc->base == MAP_FAILED, "mmap", fn).s) goto failed;

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
// lock + rc + type
#define RCS (sizeof(int)+sizeof(int)+sizeof(short int))
#define rc_t int
#define PZ_CELL_SIZE (PZ_STATIC_ALLOC_SIZE - RCS)

#ifdef sizeof(size_t) != 8
#error sizeof(size_t) must be 8 bytes!!
#endif

#define PZ_TYPE_BOOL 0
#define PZ_TYPE_FLOAT 1
#define PZ_TYPE_INT 2
#define PZ_TYPE_SPECIAL 3
#define PZ_BASIC_TYPE_BOUNDARY 4

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
  Id string_refs;
  Id string_refs_dict;
  Id gc;
} pz_mem_descriptor_t;

typedef struct {
  int lock_pid;
  int rc_dummy; 
  Id next;
  size_t size;
} pz_mem_chunk_descriptor_t;

#define PZ_VA_START 7
size_t pz_header_size() { return PZ_STATIC_ALLOC_SIZE * PZ_VA_START; }
Id pz_header_size_ssa() { Id a; PZ_ADR(a) = PZ_VA_START; return a; }
#define pz_md __pz_md(b)
void *pz_heap = 0;
void *pz_perf = 0;

pz_mem_descriptor_t *__pz_md(void *b) { return b; }


#define VA_TO_PTR0(va) \
  ((va).s ? b + RCS + ((size_t)PZ_ADR(va) * PZ_STATIC_ALLOC_SIZE) : 0) 
#define PTR_TO_VA(va, p) \
  PZ_ADR(va) = (int)(((p) - RCS - (char *)b) / PZ_STATIC_ALLOC_SIZE);

#define P_0_R(p, r) if (!(p)) { printf("From %s:%d\n", __func__, __LINE__); return (r); }
#define P_0_R2(w, l, p, r) if (!(p)) { printf("From %s:%d\n", w, l); return (r); }
#define VA_0_R(va, r) if (!(va).s) { return (r); }
#define VA_TO_PTR(va) (__ca(b, va, __func__, __LINE__) ? VA_TO_PTR0(va) : 0 )
#define VA_TO_PTR2(va) (__ca(b, va, w, l) ? VA_TO_PTR0(va) : 0 )

int __ca(void *b, Id va, WL) {
  char *p0 = VA_TO_PTR0(va); P_0_R(p0, 1); 
  rc_t *rc = (rc_t *)(p0 - RCS + sizeof(int));
  if ((*rc) == 0) { printf("[%s:%d] error: VA %x is not allocated!\n", w, l, PZ_ADR(va)); abort(); }
  return 1;
}

int cnil(Id i) { return i.s == pzNil.s || PZ_TYPE(i) < PZ_BASIC_TYPE_BOUNDARY; }
Id cb(int i) { return i ? pzTrue : pzNil; }

#define pz_md_first_free VA_TO_PTR0((va_first = pz_md->first_free))

int pz_var_free(void *b) {
    return (pz_md->total_size - pz_md->heap_size) / PZ_STATIC_ALLOC_SIZE; }
  

#define PZ_TYPE_STRING 4
#define PZ_TYPE_SYMBOL 5
#define PZ_TYPE_CFUNC 6
#define PZ_TYPE_HASH 7
#define PZ_TYPE_HASH_PAIR 8
#define PZ_TYPE_ARRAY 9
#define PZ_TYPE_REGEXP 10
#define PZ_TYPE_MAX 10

#ifdef PZ_GC_DEBUG
#define pz_retain(from, va) __pz_retain(__func__, __LINE__, b, from, va)
#define pz_retain2(from, va) __pz_retain(w, l, b, from, va)
#else
#define pz_retain(from, va) __pz_retain(b, va)
#define pz_retain2(from, va) __pz_retain(b, va)
#endif

#ifdef PZ_GC_DEBUG
Id __pz_retain(WLB, Id from, Id va);
#else
Id __pz_retain(void *b, Id va);
#endif
#define PZ_HEAP_SIZE \
    ((PZ_MEM_SIZE / PZ_STATIC_ALLOC_SIZE) * PZ_STATIC_ALLOC_SIZE)
int pz_init_memory(void *b, size_t size) {
  size_t s = size - pz_header_size();
  Id va_first;
  if (pz_md->magic != PZ_DB_MAGIC) {
    pz_md->first_free = pz_header_size_ssa();
    pz_md->total_size = s;
    pz_mem_chunk_descriptor_t *c = pz_md_first_free;
    c->next.s = 0;
    c->lock_pid = 0;
    c->size = s;

    PZ_ADR(pz_md->symbol_interns) = 1;
    PZ_TYPE(pz_md->symbol_interns) = PZ_TYPE_HASH; 
    pz_retain(pzNil, pz_md->symbol_interns);

    PZ_ADR(pz_md->string_interns) = 2;
    PZ_TYPE(pz_md->string_interns) = PZ_TYPE_HASH; 
    pz_retain(pzNil, pz_md->string_interns);

    PZ_ADR(pz_md->globals) = 3;
    PZ_TYPE(pz_md->globals) = PZ_TYPE_HASH; 
    pz_retain(pzNil, pz_md->globals);

    PZ_ADR(pz_md->string_refs) = 4;
    PZ_TYPE(pz_md->string_refs) = PZ_TYPE_ARRAY; 
    pz_retain(pzNil, pz_md->string_refs);

    PZ_ADR(pz_md->string_refs_dict) = 5;
    PZ_TYPE(pz_md->string_refs_dict) = PZ_TYPE_HASH; 
    pz_retain(pzNil, pz_md->string_refs_dict);

    PZ_ADR(pz_md->gc) = 6;
    PZ_TYPE(pz_md->gc) = PZ_TYPE_HASH;  // fake hash
    pz_retain(pzNil, pz_md->gc);

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

char *pz_type_to_cp(short int t);

int pz_perf_mode = 0;

void pz_alloc_debug(void *b, char *p, short int type) {
  return;
  if (!pz_perf_mode || b != pz_perf) return;
  char *n = b == pz_perf ? "perf" : "scheme";
  printf("[%s:%lx] alloc %lx type: %s\n", n, (size_t)b, (size_t)p, 
      pz_type_to_cp(type));
}

inline Id pz_atomic_cas_id(volatile Id *v, Id new, Id old) {
    return (Id)pz_atomic_casq((size_t *)v, new.s, old.s); }

int pz_lock_debug = 0;

#define pz_lock_p(p) __pz_lock_p(__func__, __LINE__, p)
int __pz_lock_p(WL, char *_p) { 
  if (!_p) return 0;
  char *p = _p - RCS;
  if (pz_lock_debug) printf("[%s:%d] lock: %lx\n", w, l, (size_t)p);
  size_t c = 0;
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
  int r = pz_atomic_casl(pl, pid, ov);
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

#define LI if (!va.s || va.t.type < PZ_BASIC_TYPE_BOUNDARY) { return 0; }; \
  char *p0 = VA_TO_PTR0(va); \
  P_0_R(p0, 0); char *p = (char *)p0;


#define pz_lock_va(va) __pz_lock_va(__func__, __LINE__, b, va)
int __pz_lock_va(WLB, Id va) { LI; return __pz_lock_p(w, l, p); }
#define pz_unlock_va(va) __pz_unlock_va(__func__, __LINE__, b, va)
int __pz_unlock_va(WLB, Id va) { LI; return __pz_unlock_p(w, l, p); }

#define pz_symbol_interns pz_md->symbol_interns
#define pz_string_interns pz_md->string_interns
#define pz_globals pz_md->globals
#define pz_string_refs pz_md->string_refs
#define pz_string_refs_dict pz_md->string_refs_dict


#define pz_lock_header() __pz_lock_header(__func__, __LINE__, b)
int __pz_lock_header(WLB) { return __pz_lock_va(w, l, b, pzHeader); }

#define pz_unlock_header() __pz_unlock_header(__func__, __LINE__, b)
int __pz_unlock_header(WLB) { return __pz_unlock_va(w, l, b, pzHeader); }

#define pz_lock_gc() __pz_lock_gc(__func__, __LINE__, b)
int __pz_lock_gc(WLB) { return __pz_lock_va(w, l, b, pz_md->gc); }

#define pz_unlock_gc() __pz_unlock_gc(__func__, __LINE__, b)
int __pz_unlock_gc(WLB) { return __pz_unlock_va(w, l, b, pz_md->gc); }

size_t pz_alloc_counter = 0;
int pz_alloc_locked = 0;
Id __pz_valloc(void *b, const char *where, short int type) {
  Id va_first;
  pz_alloc_counter++;
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
    if (ns.s != va_first.s) { printf("alloc first failed\n"); goto retry; }
    PTR_TO_VA(r, (char *)c);
    //printf("alloc size: %x\n", PZ_ADR(r));
  } else {
    //printf("alloc sub\n");
    // chunk is larger than wanted 
    size_t ns, os;
    os = c->size;
    ns = pz_atomic_sub(&c->size, PZ_STATIC_ALLOC_SIZE);
    if (ns != os) { printf("alloc sub failed\n"); goto retry; }
    PTR_TO_VA(r, (char *)c + c->size);
  }
  if (!c->next.s) { pz_md->heap_size += PZ_STATIC_ALLOC_SIZE; }
  //printf("heap size: %ld\n", pz_md->heap_size);
  if (r.s) { 
    PZ_TYPE(r) = type; 
    pz_lock_va(r);
    char *p = VA_TO_PTR0(r);
    rc_t *rc = (rc_t *) (p - RCS + sizeof(int));
    *rc = 0x1;
    //*rc = PZ_MAX_INT_VALUE;
    //pz_alloc_debug(b, (char *)rc, type);
    short int *t = (short int *)(p - sizeof(short int));
    *t = type;
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

int pz_zero(void *b, Id va) { 
  char *p = VA_TO_PTR0(va); P_0_R(p, 0); 
  memset(p, 0, PZ_CELL_SIZE); return 1;}

#define PZ_ALLOC(va, type) va = pz_valloc(b, __func__, type); VA_0_R(va, pzNil);
#define PZ_ALLOC2(va, type, r) va = pz_valloc(b, __func__, type); VA_0_R(va, r);

int pz_free(void *b, Id va) {
  //printf("pz_free\n");
  int t = PZ_TYPE(va);
  if (t == PZ_TYPE_BOOL || t == PZ_TYPE_FLOAT || t == PZ_TYPE_INT) return 0;
  char *used_chunk_p = VA_TO_PTR(va); P_0_R(used_chunk_p, 0);
  pz_mem_chunk_descriptor_t *mcd_used_chunk = 
      (pz_mem_chunk_descriptor_t *)used_chunk_p;
  pz_lock_header();
  mcd_used_chunk->size = PZ_STATIC_ALLOC_SIZE;
  mcd_used_chunk->rc_dummy = 0;
  while (1) {
    Id o = mcd_used_chunk->next = pz_md->first_free;
    Id r = pz_atomic_cas_id(&pz_md->first_free, va, o);
    if (o.s == r.s) goto finish;
    printf("free failed! try again\n");
  }
finish:
  pz_unlock_header();
  return 1;
}

/*
 * Register types.
 */

Id pz_int(int i) { 
    Id va; PZ_TYPE(va) = PZ_TYPE_INT; PZ_INT(va) = i; return va; }

Id pz_float(float f) { 
    Id va; PZ_TYPE(va) = PZ_TYPE_FLOAT; PZ_FLOAT(va) = f; return va; }

Id cn(Id v) { return PZ_TYPE(v) == PZ_TYPE_BOOL ? pz_int(v.s ? 1 : 0) : v; }

/*
 * Basic types 
 */


char *pz_types_s[] = {"nil", "float", "int", "special", "string", "symbol", "cfunc", "hash", 
    "hash pair", "array"};
char *pz_types_i[] = {"x", "f", "i", "S", "s", ":", "C", "{", "P", "["};

char *pz_type_to_cp(short int t) {
  if (t > PZ_TYPE_MAX || t < 0) { return "<unknown>"; }
  return pz_types_s[t];
}

char *pz_type_to_i_cp(short int t) {
  if (t > PZ_TYPE_MAX || t < 0) { return "?"; }
  return pz_types_i[t];
}

int pz_is_string(Id va) { 
    return PZ_TYPE(va) == PZ_TYPE_SYMBOL || PZ_TYPE(va) == PZ_TYPE_STRING; }
int pz_is_number(Id va) { 
    return PZ_TYPE(va) == PZ_TYPE_FLOAT || PZ_TYPE(va) == PZ_TYPE_INT; }
int c_type(int t) { return t == PZ_TYPE_SYMBOL ? PZ_TYPE_STRING : t;}
int pz_is_type_i(Id va, int t) { return c_type(PZ_TYPE(va)) == c_type(t); }
#define S(s) pz_string_new_c(b, s)


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

#define __PZ_TYPED_VA_TO_PTR(ptr, va, type, r, check) \
  PZ_CHECK_TYPE((va), (type), (r)); (ptr) = check((va)); P_0_R((ptr), (r));
#define __PZ_TYPED_VA_TO_PTR2(ptr, va, type, r, check) \
  PZ_CHECK_TYPE2(w, l, (va), (type), (r)); (ptr) = check((va)); P_0_R((ptr), (r));
#define PZ_TYPED_VA_TO_PTR(p,v,t,r) __PZ_TYPED_VA_TO_PTR(p,v,t,r,VA_TO_PTR)
#define PZ_TYPED_VA_TO_PTR2(p,v,t,r) __PZ_TYPED_VA_TO_PTR2(p,v,t,r,VA_TO_PTR2)
#define PZ_TYPED_VA_TO_PTR0(p,v,t,r) __PZ_TYPED_VA_TO_PTR(p,v,t,r,VA_TO_PTR0)

/*
 * Reference counting.
 */

#define RCI if (!va.s || va.t.type < PZ_BASIC_TYPE_BOUNDARY) { return va; }; \
  char *p0 = VA_TO_PTR0(va); \
  P_0_R(p0, pzNil); rc_t *rc = (rc_t *)(p0 - RCS + sizeof(int));

int pz_ary_free(void *b, Id);
int pz_ht_free(void *b, Id);

#define pz_release(va) __pz_release(b, va)
Id __pz_release(void *b, Id va) { 
  RCI; PZ_CHECK_ERROR((*rc <= 1), "Reference counter is already 0!", pzNil);
#ifdef PZ_GC_DEBUG
  pz_var_status[PZ_ADR(va)].release_counter++;
#endif
  int rv, ov;
  do {
    ov =  *rc;
    rv = pz_atomic_subl(rc, 1);
  } while (rv != ov);
  return va;
}

Id pz_delete(void *b, Id va) { 
  RCI; 
  //printf("pz_delete: rc: %d\n", (*rc));
  if ((*rc) == 0x0) return pzNil; // ignore, so one can jump at random address!
  PZ_CHECK_ERROR((*rc != 1), "Cannot delete, rc != 0!", pzNil);
  switch (PZ_TYPE(va)) {
    case PZ_TYPE_ARRAY: pz_ary_free(b, va); break;
    case PZ_TYPE_HASH: pz_ht_free(b, va); break;
    case PZ_TYPE_HASH_PAIR: /* ignore: will always be freed by hash */; break;
    case PZ_TYPE_REGEXP: pz_rx_free(b, va); break; 
    default: pz_free(b, va); break;
  }
  (*rc) = 0x0;
  return pzTrue;
}

#define PZ_DUMP_INSPECT 0x1
#define PZ_DUMP_DEBUG 0x2
#define PZ_DUMP_RECURSE 0x4
void pz_print_dump(void *b, Id va, int flags);

size_t __pz_mem_dump(void *b, int silent) {
  size_t entries = pz_md->heap_size / PZ_STATIC_ALLOC_SIZE;
  size_t mem_start = pz_md->total_size + pz_header_size() - 
      pz_md->heap_size;
#ifndef PZ_GC_DEBUG
  int debug = 0;
#endif


  if (!silent && debug) printf("totalsize: %ld\n", pz_md->total_size);
  char *p = mem_start + b + sizeof(int);
  size_t i;
  size_t active_entries = 0;
  if (!silent && debug) printf("[%lx] mem dump: entries: %ld\n", (size_t)b, entries);
  for (i = 0; i < entries; ++i, p += PZ_STATIC_ALLOC_SIZE) {
    rc_t *rc = (rc_t *)p;
    if (*rc > 0) {
      active_entries++;
      short int *t = (short int *) (p + sizeof(int));
      Id r;
      PTR_TO_VA(r, (char *)p - sizeof(int) + RCS);
      PZ_TYPE(r) = *t;
#ifdef PZ_GC_DEBUG
      if (debug) {
        pz_var_status_t *s = &pz_var_status[PZ_ADR(r)];
        if (!silent) {
          //printf("%s%x:%d%s ", pz_var_status[PZ_ADR(r)].new ? "NEW" : "",
          //    PZ_ADR(r), *rc, pz_type_to_i_cp(*t));
          if (s->new) {
            printf("NEW: %d %s:%d ", *rc, s->where, s->line );
            pz_print_dump(b, r, PZ_DUMP_DEBUG);
            if (s->retain_where) {
              printf("retain from %s:%d %x %ld:%ld", 
                  s->retain_where,
                  s->retain_line, s->retain_adr, s->retain_counter, 
                  s->release_counter);
            }
            printf("\n");
          }
        }
      }
      pz_var_status[PZ_ADR(r)].new = 0;
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

size_t pz_max(size_t a, size_t b) { return a > b ? a : b; }
size_t pz_min(size_t a, size_t b) { return a < b ? a : b; }

#define pz_garbage_collect(b) __pz_garbage_collect(b, 0);
#define pz_garbage_collect_full(b) __pz_garbage_collect(b, 1);
void __pz_garbage_collect(void *b, int full) {
  pz_lock_header();
  size_t entries = pz_md->heap_size / PZ_STATIC_ALLOC_SIZE;
  if (!full && pz_alloc_counter < 1000) entries = 10;
  else pz_alloc_counter = 0;
  size_t mem_start = pz_md->total_size + pz_header_size() - 
      pz_md->heap_size;
  pz_unlock_header();
  pz_lock_gc();
  char *p = mem_start + b + sizeof(int);
  size_t i;
  for (i = 0; i < entries; ++i, p += PZ_STATIC_ALLOC_SIZE) {
    char *pp = p - sizeof(int) + RCS;
    pz_lock_p(pp);
    rc_t *rc = (rc_t *)p;
    short int *t = (short int *) (p + sizeof(int));
    if (*rc == 1) {
      Id va;
      PTR_TO_VA(va, p - sizeof(int) + RCS);
      PZ_TYPE(va) = *t;
#ifdef PZ_GC_DEBUG
      if (debug) {
        printf("GC delete: ");
        pz_print_dump(b, va, PZ_DUMP_DEBUG);
        printf("\n");
      }
#endif
      pz_delete(b, va);
    }
    pz_unlock_p(pp);
  }
  pz_unlock_gc();
}

#ifdef PZ_GC_DEBUG
Id __pz_retain(WLB, Id va_from, Id va) { 
#else
Id __pz_retain(void *b, Id va) { 
#endif

  RCI;
#ifdef PZ_GC_DEBUG
  pz_var_status[PZ_ADR(va)].retain_where = w;
  pz_var_status[PZ_ADR(va)].retain_line = l;
  pz_var_status[PZ_ADR(va)].retain_adr = PZ_ADR(va_from);
  pz_var_status[PZ_ADR(va)].retain_counter++;
#endif
  int rv, ov, nv;
  do {
    ov =  *rc;
    nv = ov == PZ_MAX_INT_VALUE ? 2 : ov + 1;
    rv = pz_atomic_casl(rc, nv, ov);
  } while (rv != ov);
  //int rv, ov;
  //do {
  //  ov =  *rc;
  //  rv = pz_atomic_addl(rc, 1);
  //} while (rv != ov);
  return va; 
}

/*
 * String
 */

#define PZ_STR_MAX_LEN (PZ_CELL_SIZE - sizeof(pz_string_size_t))

int pz_strdup(void *b, Id va_dest, char *source, pz_string_size_t l) {
  char *p; PZ_TYPED_VA_TO_PTR0(p, va_dest, PZ_TYPE_STRING, 0);
  PZ_CHECK_ERROR((l + 1 > PZ_STR_MAX_LEN), "strdup: string too large", 0);
  *(pz_string_size_t *) p = l;
  p += sizeof(pz_string_size_t);
  memcpy(p, source, l);
  p += l;
  (*p) = 0x0;
  return 1;
}

#define pz_string_new(b, s, l) __pz_string_new(__func__, __LINE__, b, s, l)
Id __pz_string_new(WLB, char *source, pz_string_size_t len) { 
  Id va; PZ_ALLOC(va, PZ_TYPE_STRING);
  pz_register_var(va, w, l);
  if (!pz_strdup(b, va, source, len)) return pzNil;
  return va;
}

#define pz_string_new_c(b, s) __pz_string_new_c(__func__, __LINE__, b, s)
Id __pz_string_new_c(WLB, char *source) { 
    return __pz_string_new(w, l, b, source, strlen(source)); }
#include "debug.c"

Id __pz_snn(void *b, Id n, const char *f) { 
  Id va; PZ_ALLOC(va, PZ_TYPE_STRING);
  int i = PZ_TYPE(n) == PZ_TYPE_INT;
  char ns[1024]; 
  i ? snprintf(ns, 1023, f, PZ_INT(n)) : 
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

#define pz_string_sub_str_new(b, s, st, c) \
    __pz_string_sub_str_new(__func__, __LINE__, b, s, st, c)
Id __pz_string_sub_str_new(WLB, Id s, int start, 
    int _count) {
  PZ_ACQUIRE_STR_D(dt, s, pzNil);
  if (start > dt.l) start = dt.l;
  int count = (_count < 0) ? (dt.l + _count + 1) - start : _count;
  if (count < 0) count = 0;
  if (count > dt.l - start) count = dt.l - start;
  char sym[dt.l + 1];
  memcpy(&sym, dt.s + start, count);
  return __pz_string_new(w, l, b, (char *)&sym, count);
}

#define pz_string_new_0(b) __pz_string_new_0(__func__, __LINE__, b)
Id __pz_string_new_0(WLB) { return __pz_string_new(w, l, b, "", 0); }

int __pz_acquire_string_data(WLB, Id va_s, pz_str_d *d) { 
  char *s; PZ_TYPED_VA_TO_PTR2(s, va_s, PZ_TYPE_STRING, 0);
  d->s = s + sizeof(pz_string_size_t); d->l = *(pz_string_size_t *) s; 
  return 1;
}

char *__pz_string_ptr(WLB, Id va_s) { 
    if (cnil(va_s)) return 0;
    PZ_ACQUIRE_STR_D2(ds, va_s, 0x0); return ds.s; }

Id pz_string_append(void *b, Id va_d, Id va_s) {
  PZ_ACQUIRE_STR_D(dd, va_d, pzNil); PZ_ACQUIRE_STR_D(ds, va_s, pzNil);
  size_t l = dd.l + ds.l;
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

#define pz_string_equals_cp_i(s, sb)  \
    __pz_string_equals_cp_i(__func__, __LINE__, b, s, sb)
int __pz_string_equals_cp_i(WLB, Id va_s, char *sb) {
  PZ_ACQUIRE_STR_D2(ds, va_s, 0); 
  size_t bl = strlen(sb);
  if (ds.l != bl) { return 0; }
  pz_string_size_t i;
  for (i = 0; i < ds.l; i++) { if (ds.s[i] != sb[i]) return 0; }
  return 1;
}

void __cp(char **d, char **s, size_t l, int is) {
    memcpy(*d, *s, l); (*d) += l; if (is) (*s) += l; }

int pz_string_starts_with(void *b, Id va_s, Id va_q) {
  PZ_ACQUIRE_STR_D(ds, va_s, 0); PZ_ACQUIRE_STR_D(dq, va_q, 0); 
  if (dq.l > ds.l) return 0;
  return strncmp(ds.s, dq.s, dq.l) == 0;
}

Id pz_string_replace(void *b, Id va_s, Id va_a, Id va_b) {
  PZ_ACQUIRE_STR_D(ds, va_s, pzNil); PZ_ACQUIRE_STR_D(da, va_a, pzNil); 
  PZ_ACQUIRE_STR_D(db, va_b, pzNil); 
  Id va_new = pz_string_new_0(b); PZ_ACQUIRE_STR_D(dn, va_new, pzNil);
  char *dp = dn.s, *sp = ds.s; P_0_R(dp, pzNil)
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
  *(pz_string_size_t *)(dn.s - sizeof(pz_string_size_t)) = dp - dn.s;
  return va_new;
}

/*
 * general var handling
 */

size_t pz_hash_var(void *b, Id va) {
  if (PZ_TYPE(va) == PZ_TYPE_STRING) {
    size_t h;
    pz_string_hash(b, va, &h);
    return h;
  }
  return va.s;
}

#define pz_ary_len(b, a) __pz_ary_len(__FUNCTION__, __LINE__, b, a)
int __pz_ary_len(WLB, Id va_ary);

Id cnil2(void *b, Id i) { 
    return PZ_TYPE(i) == PZ_TYPE_ARRAY && pz_ary_len(b, i) == 0 ? pzNil : i; }

#define pz_equals_i(a, o) __pz_equals_i(b, a, o)
int __pz_equals_i(void *b, Id a, Id o) {
  if (PZ_TYPE(a) == PZ_TYPE_STRING && PZ_TYPE(o) == PZ_TYPE_STRING) {
     PZ_ACQUIRE_STR_D(da, a, 0); PZ_ACQUIRE_STR_D(db, o, 0); 
     if (da.l != db.l) return 0;
     pz_string_size_t i;
     for (i = 0; i < da.l; i++) {
        if (da.s[i] != db.s[i]) return 0; }
     return 1;
  } 
  return cnil2(b, a).s == cnil2(b, o).s;
}

Id pz_to_symbol(Id va_s) {
  if (PZ_TYPE(va_s) == PZ_TYPE_SYMBOL) return va_s;
  if (PZ_TYPE(va_s) != PZ_TYPE_STRING) return pzNil;
  Id s = va_s;
  PZ_TYPE(s) = PZ_TYPE_SYMBOL;
  return s;
}

/*
 * Hashtable
 */

typedef struct {
  Id va_key;
  Id va_value;
  Id va_next;
} pz_ht_entry_t;
#define PZ_HT_BUCKETS ((PZ_CELL_SIZE - (2 * sizeof(Id))) / sizeof(Id))
typedef struct {
  int size;
  Id va_buckets[PZ_HT_BUCKETS];
  Id va_parent;
} pz_hash_t;

#define pz_ht_new(b) __pz_ht_new(__func__, __LINE__, b)
Id __pz_ht_new(WLB) {
    Id va_ht; 
    PZ_ALLOC(va_ht, PZ_TYPE_HASH); 
    pz_register_var(va_ht, w, l);
    pz_lock_va(va_ht);
    pz_zero(b, va_ht); 
    pz_unlock_va(va_ht);
    return va_ht; }

size_t pz_ht_hash(void *b, Id va_s) {
    return pz_hash_var(b, va_s) % PZ_HT_BUCKETS; }

pz_ht_entry_t pz_ht_null_node = { 0, 0, 0 };

#define PZ_HT_ITER_BEGIN(r) \
  Id va_hr; pz_ht_entry_t *hr = &pz_ht_null_node; \
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR2(ht, va_ht, PZ_TYPE_HASH, (r)); \
  size_t k = pz_ht_hash(b, va_key); \
  for (va_hr = ht->va_buckets[k];  \
      va_hr.s != 0 && hr != NULL; ) { \
    PZ_TYPED_VA_TO_PTR(hr, va_hr, PZ_TYPE_HASH_PAIR, (r)); \
    if (!hr || !pz_equals_i(va_key, hr->va_key)) goto next; 

#define PZ_HT_ITER_END(v) } return (v);

#define pz_ht_lookup(b, hr, ht, key)  __pz_ht_lookup(w, l, b, hr, ht, key)
int __pz_ht_lookup(WLB, pz_ht_entry_t **_hr, Id va_ht, Id va_key) {
  (*_hr) = &pz_ht_null_node; 
  PZ_HT_ITER_BEGIN(0) 
    (*_hr) = hr;
    return 1;
    next: va_hr = hr->va_next;
  PZ_HT_ITER_END(0);
}

#define pz_ht_delete(b, ht, key)  __pz_ht_delete(w, l, b, ht, key)
Id __pz_ht_delete(WLB, Id va_ht, Id va_key) {
  Id va_p = pzNil;
  PZ_HT_ITER_BEGIN(pzNil);
    pz_ht_entry_t *p = VA_TO_PTR(va_p);
    if (p) { p->va_next = hr->va_next; }
    else { ht->va_buckets[k] = pzNil; }
    pz_release(hr->va_value); pz_release(hr->va_key); pz_free(b, va_hr);
    ht->size -= 1;
    return pzTrue; 
  next: va_p = va_hr;
  PZ_HT_ITER_END(pzTrue);
}

int __pz_ht_free(void *b, Id va_ht) {
  int k; Id va_hr, va_p = pzNil; pz_ht_entry_t *hr = &pz_ht_null_node; 
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(ht, va_ht, PZ_TYPE_HASH, 0); 
  for (k = 0; k < PZ_HT_BUCKETS; k++) {
    for (va_hr = ht->va_buckets[k]; va_hr.s != 0 && hr != NULL; va_hr = hr->va_next) {
      PZ_TYPED_VA_TO_PTR(hr, va_hr, PZ_TYPE_HASH_PAIR, 0); 
      pz_release(hr->va_value); pz_release(hr->va_key); 
      if (va_p.s) { pz_release(va_p); pz_free(b, va_p); }
      va_p = va_hr;
    }
  }
  if (va_p.s) { pz_release(va_p); pz_free(b, va_p); }
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
    PZ_TYPED_VA_TO_PTR(h->ht, va_ht, PZ_TYPE_HASH, 0); 
    h->initialized = 1;
  }
next_bucket:
  if (h->k >= PZ_HT_BUCKETS) return 0;
  if (!h->va_hr.s) { h->va_hr = h->ht->va_buckets[h->k];  new_bucket = 1;}
  if (!h->va_hr.s) { h->k++; goto next_bucket; }
  if (new_bucket) goto return_hr;
next_pair:
  h->va_hr = h->hr->va_next; 
  if (!h->va_hr.s) { h->k++; goto next_bucket; }
return_hr:
  //CDS("pzNil", pzNil);
  //CDS("va_hr", h->va_hr);
  PZ_TYPED_VA_TO_PTR(h->hr, h->va_hr, PZ_TYPE_HASH_PAIR, 0); 
  if (!h->hr) goto next_pair;
  return h->hr;
}

Id pz_ht_map(void *b, Id va_ht, Id (*func_ptr)(void *b, Id)) {
  pz_ht_iterate_t h;
  h.initialized = 0;
  pz_ht_entry_t *hr;
  Id r = pz_ary_new(b);
  while ((hr = pz_ht_iterate(b, va_ht, &h))) {
    Id s = pz_string_new_0(b);
    pz_string_append(b, s, func_ptr(b, hr->va_key));
    pz_string_append(b, s, S(" => "));
    pz_string_append(b, s, func_ptr(b, hr->va_value));
    pz_ary_push(b, r, s);
  }
  return r;
}

#define pz_ht_get(b, ht, key) __pz_ht_get(__func__, __LINE__, b, ht, key)
Id __pz_ht_get(WLB, Id va_ht, Id va_key) { 
  pz_ht_entry_t *hr; pz_ht_lookup(b, &hr, va_ht, va_key);  P_0_R(hr, pzNil);
  return hr->va_value;
}

int pz_ht_size(void *b, Id va_ht) { 
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(ht, va_ht, PZ_TYPE_HASH, 0);
  return ht->size;
}

#define pz_ht_set(b, va_ht, va_key, va_value) \
  __pz_ht_set(__func__, __LINE__, b, va_ht, va_key, va_value)
Id __pz_ht_set(WLB, Id va_ht, Id va_key, Id va_value) {
// XXX: May need to be locked when sharedly using a global dict, like
// globals!
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(ht, va_ht, PZ_TYPE_HASH, pzNil);
  pz_ht_entry_t *hr; pz_ht_lookup(b, &hr, va_ht, va_key);
  size_t v;
  int new_entry = !hr->va_value.s;
  Id va_hr;
  if (new_entry) { 
    v = pz_ht_hash(b, va_key);
    PZ_ALLOC(va_hr, PZ_TYPE_HASH_PAIR);
    pz_register_var(va_hr, w, l);
    pz_retain2(va_ht, va_hr); hr = VA_TO_PTR(va_hr); P_0_R(hr, pzNil);
    hr->va_key = pz_retain2(va_hr, va_key);
    ht->size += 1;
  } else {
    pz_release(hr->va_value);
  }

  hr->va_value = pz_retain2(va_hr, va_value);

  if (new_entry) {
    hr->va_next = ht->va_buckets[v];
    ht->va_buckets[v] = va_hr;
  }
  return va_value;
}

Id pz_ht_inc(void *b, Id va_ht, Id va_key) {
  Id v = pz_ht_get(b, va_ht, va_key);
  if (cnil(v)) v = pz_int(0);
  if (!pz_is_number(v)) return pzNil;
  Id vn = pz_int(PZ_INT(v) + 1);
  return pz_ht_set(b, va_ht, va_key, pz_int(PZ_INT(v) + 1));
}

#define pz_intern(s) __pz_intern(b, s)
Id ___pz_intern(void *b, Id va_s) { 
  //if (PZ_TYPE(va_s) == PZ_TYPE_SYMBOL) PZ_TYPE(va_s) = PZ_TYPE_STRING;
  Id dict = PZ_TYPE(va_s) == PZ_TYPE_SYMBOL ? 
      pz_symbol_interns : pz_string_interns;
  Id sv = va_s; PZ_TYPE(sv) = PZ_TYPE_STRING;
  Id va = pz_ht_get(b, dict, sv); 
  if (va.s) { return va; }
  //Id va_sym = va_s; PZ_TYPE(va_sym) = PZ_TYPE_SYMBOL;
  if (cnil(pz_ht_set(b, dict, sv, va_s))) return pzNil;
  return pz_ht_get(b, dict, sv); 
}

Id __pz_intern(void *b, Id va_s) { 
  //CDS("intern <- ", va_s);
  Id r = ___pz_intern(b, va_s);
  //CDS("intern -> ", r);
  return r;
}


int pz_is_interned(void *b, Id va_s) {
  Id dict = PZ_TYPE(va_s) == PZ_TYPE_SYMBOL ? 
      pz_symbol_interns : pz_string_interns;
  Id sv = va_s; PZ_TYPE(sv) = PZ_TYPE_STRING;
  return pz_ht_get(b, dict, sv).s != 0; 
}

Id pz_env_new(void *b, Id va_ht_parent) {
  Id va = pz_ht_new(b);
  pz_hash_t *ht; PZ_TYPED_VA_TO_PTR(ht, va, PZ_TYPE_HASH, pzNil);
  ht->va_parent = va_ht_parent;
  return va;
}

#define PZ_ENV_FIND \
  Id va0 = va_ht, found = pzNil; \
  while (va_ht.s && !(found = __pz_ht_get(w, l, b, va_ht, va_key)).s) { \
    pz_hash_t *ht; PZ_TYPED_VA_TO_PTR2(ht, va_ht, PZ_TYPE_HASH, pzNil); \
    va_ht = ht->va_parent; \
  }

#define pz_env_find(b, ht, key) __pz_env_find(__func__, __LINE__, b, ht, key)
Id __pz_env_find(WLB, Id va_ht, Id va_key) { 
  PZ_ENV_FIND; 
  return found; 
}

#define pz_env_find_and_set(b, ht, k, v) \
    __pz_env_find_and_set(__func__, __LINE__, b, ht, k, v)
Id __pz_env_find_and_set(WLB, Id va_ht, Id va_key, Id va_value) { 
  PZ_ENV_FIND;
  if (found.s) { return pz_ht_set(b, va_ht, va_key, va_value); }
  else { return pz_ht_set(b, va0, va_key, va_value); }
}

void pz_add_globals(void *b, Id env);

void pz_setup() {
  PZ_TYPE(pzTrue) = PZ_TYPE_BOOL;
  pzTrue.t.d.i = 1;
  PZ_TYPE(pzTail) = PZ_TYPE_SPECIAL;
  PZ_INT(pzTail)  = 1;
  PZ_TYPE(pzError) = PZ_TYPE_SPECIAL;
  PZ_INT(pzError)  = 2;
  PZ_TYPE(pzHeader) = PZ_TYPE_HASH; // fake hash
  PZ_ADR(pzHeader)  = 0;
  pid = getpid();
}

char *cmd;

char *pz_cmd_display() { return pz_perf_mode ? "perf" : "ponzi"; }

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
          PZ_VERSION, pz_var_free(b));
  return b;
}

/*
 * FFI
 */

typedef struct { Id (*func_ptr)(void *b, Id, Id); Id name; } pz_cfunc_t;

Id pz_define_func(void *b, char *name, Id (*p)(void *b, Id, Id), Id env) { 
  Id va_f; PZ_ALLOC(va_f, PZ_TYPE_CFUNC);
  pz_cfunc_t *cf; PZ_TYPED_VA_TO_PTR0(cf, va_f, PZ_TYPE_CFUNC, pzNil);
  cf->func_ptr = p;
  cf->name = pz_intern(pz_to_symbol(S(name)));
  pz_ht_set(b, env, cf->name, va_f);
  return pzTrue;
}

Id pz_call(void *b, Id va_f, Id env, Id x) { 
  pz_cfunc_t *cf; PZ_TYPED_VA_TO_PTR(cf, va_f, PZ_TYPE_CFUNC, pzNil);
  Id r = cf->func_ptr(b, env, x);
  return r;
}

/*
 * Array
 */

#define PZ_ARY_MAX_ENTRIES ((PZ_CELL_SIZE - sizeof(Id)) / sizeof(Id))
typedef struct {
  int size;
  int start; 
  int lambda;
  Id va_entries[PZ_ARY_MAX_ENTRIES];
} ht_array_t;

Id __pz_ary_new(WLB) {
  Id va_ary; PZ_ALLOC(va_ary, PZ_TYPE_ARRAY); 
  pz_register_var(va_ary, w, l);
  pz_zero(b, va_ary); return va_ary; 
}

void __ary_retain_all(void *b, Id from, ht_array_t *a) {
  int i = 0; 
  for (i = a->start; i < a->size; i++) pz_retain(from, a->va_entries[i]);
}

#define pz_ary_clone(b, va_s) __pz_ary_clone(b, va_s, -1, -1)
#define pz_ary_clone_part(b, va_s, s, c) __pz_ary_clone(b, va_s, s, c)
Id __pz_ary_clone(void *b, Id va_s, int start, int count) {
  ht_array_t *ary_s; PZ_TYPED_VA_TO_PTR(ary_s, va_s, PZ_TYPE_ARRAY, pzNil);
  Id va_c; PZ_ALLOC(va_c, PZ_TYPE_ARRAY);
  char *p_c = VA_TO_PTR(va_c), *p_s = VA_TO_PTR(va_s);
  memcpy(p_c, p_s, PZ_CELL_SIZE);
  ht_array_t *a = (ht_array_t *)p_c;
  int c = a->size - a->start;
  if (start < 0) start = 0;
  if (count < 0) count = c + count + 1;
  if (start + count > a->size) count = a->size - start;
  a->start = start;
  a->size = start + count;
  __ary_retain_all(b, va_c, a);
  return va_c;
}

int pz_ary_free(void *b, Id va_ary) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, 0);
  int i = 0;
  for (i = ary->start; i < ary->size; i++) pz_release(ary->va_entries[i]);
  pz_free(b, va_ary);
  return 1;
}

Id pz_ary_new_join(void *b, Id a, Id o) {
  ht_array_t *aa; PZ_TYPED_VA_TO_PTR(aa, a, PZ_TYPE_ARRAY, pzNil);
  ht_array_t *ab; PZ_TYPED_VA_TO_PTR(ab, o, PZ_TYPE_ARRAY, pzNil);
  Id n; PZ_ALLOC(n, PZ_TYPE_ARRAY);
  ht_array_t *an; PZ_TYPED_VA_TO_PTR(an, n, PZ_TYPE_ARRAY, pzNil);
  int aas = aa->size - aa->start;
  an->size = aas + ab->size - ab->start;
  PZ_CHECK_ERROR((an->size >= PZ_ARY_MAX_ENTRIES), "array is full", pzNil);
  memcpy(&an->va_entries, &aa->va_entries + aa->start, aas * sizeof(Id));
  memcpy(&an->va_entries[aas + 1], &ab->va_entries + ab->start, 
      (ab->size - ab->start) * sizeof(Id));
  __ary_retain_all(b, n, an);
  return n;
}

#define pz_ary_join_by_s(b, a, j) \
    __pz_ary_join_by_s(__func__, __LINE__, b, a, j)
Id __pz_ary_join_by_s(WLB, Id va_ary, Id va_js) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, pzNil);
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

Id __pz_ary_push(WLB, Id va_ary, Id va) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  PZ_CHECK_ERROR((ary->size >= PZ_ARY_MAX_ENTRIES), "array is full", pzNil);
  ary->size += 1;
  ary->va_entries[ary->start + ary->size - 1] = pz_retain2(va_ary, va);
  return va_ary;
}

int pz_ary_set_lambda(void *b, Id va_ary) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, 0);
  ary->lambda = 1;
  return 1;
}

int pz_ary_is_lambda(void *b, Id va_ary) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, 0);
  return ary->lambda;
}


Id pz_ary_map(void *b, Id va_ary, Id (*func_ptr)(void *b, Id)) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  int i;
  Id r = pz_ary_new(b);
  for (i = ary->start; i < ary->size; i++) 
      pz_ary_push(b, r, func_ptr(b, ary->va_entries[i]));
  return r;
}

Id pz_ary_unshift(void *b, Id va_ary) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  if (ary->size - ary->start <= 0) { return pzNil; } 
  ary->start++;
  return pz_release(ary->va_entries[ary->start - 1]);
}

Id pz_ary_set(void *b, Id va_ary, int i, Id va) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  PZ_CHECK_ERROR((ary->start + i >= PZ_ARY_MAX_ENTRIES), 
      "array index too large", pzNil);
  if (i - ary->start > ary->size) ary->size = i - ary->start;
  Id va_o = ary->va_entries[ary->start + i];
  if (va_o.s) pz_release(va_o);
  // XXX pz_atomic_cas
  ary->va_entries[ary->start + i] = va;
  return va;
}

Id pz_ary_pop(void *b, Id va_ary) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  if (ary->size - ary->start <= 0) { return pzNil; } 
  ary->size--;
  return pz_release(ary->va_entries[ary->start + ary->size]);
}

#define pz_ary_len(b, a) __pz_ary_len(__FUNCTION__, __LINE__, b, a)
int __pz_ary_len(WLB, Id va_ary) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR2(ary, va_ary, PZ_TYPE_ARRAY, -1);
  return ary->size - ary->start;
}

Id pz_ary_index(void *b, Id va_ary, int i) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR(ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  if (i < 0) i = ary->size - ary->start + i;
  if (ary->size - ary->start < i) { return pzNil; } 
  return ary->va_entries[ary->start + i];
}

Id ca_i(void *b, Id va_ary, int i) { return pz_ary_index(b, va_ary, i); }
#define ca_f(ary) ca_i(b, ary, 0)
#define ca_s(ary) ca_i(b, ary, 1)
#define ca_th(ary) ca_i(b, ary, 2)
#define ca_fth(ary) ca_i(b, ary, 3)

#define pz_ary_iterate(b, va_ary, i) \
  __pz_ary_iterate(__func__, __LINE__, b, va_ary, i)
Id __pz_ary_iterate(WLB, Id va_ary, int *i) {
  ht_array_t *ary; PZ_TYPED_VA_TO_PTR2(ary, va_ary, PZ_TYPE_ARRAY, pzNil);
  if (*i >= ary->size - ary->start) { return pzNil; }
  return pz_ary_index(b, va_ary, (*i)++); 
}

int pz_ary_contains_only_type_i(void *b, Id a, int t) {
  int i = 0; Id va;
  while ((va = pz_ary_iterate(b, a, &i)).s)
      if (!pz_is_type_i(va, t))  return 0;
  return 1;
}

#define PZ_PUSH_STRING { \
    int l = ds.s + i - last_start - match_pos; \
    Id va_ns = __pz_string_new(w, l, b, last_start, l); VA_0_R(va_ns, pzNil); \
    if (!pz_ary_push(b, va_ary, va_ns).s) return pzNil; }

#define pz_string_split(b, s, sep) \
    __pz_string_split(__func__, __LINE__, b, s, sep)
Id __pz_string_split(WLB, Id va_s, char sep) {
  Id va_ary = pz_ary_new(b);
  PZ_ACQUIRE_STR_D(ds, va_s, pzNil);
  if (ds.l == 0) return pzNil;
  size_t i, match_pos = 0;
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

#define PZ_ARY_MAX_ENTRIES ((PZ_CELL_SIZE - sizeof(Id)) / sizeof(Id))
typedef struct {
  Id match_s;
} pz_rx_t;

#define pz_rx_new(match_s) __pz_rx_new(__func__, __LINE__, b, match_s);
Id __pz_rx_new(WLB, Id match_s) {
  Id va_rx; PZ_ALLOC(va_rx, PZ_TYPE_REGEXP); 
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(rx, va_rx, PZ_TYPE_REGEXP, pzNil);
  pz_zero(b, va_rx);
  rx->match_s = pz_retain2(va_rx, match_s);
  pz_register_var(va_rx, w, l);
  return va_rx; 
}

int pz_rx_free(void *b, Id va_rx) {
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(rx, va_rx, PZ_TYPE_REGEXP, 0);
  pz_release(rx->match_s);
  return 1;
}

Id pz_rx_match_string(void *b, Id va_rx) {
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(rx, va_rx, PZ_TYPE_REGEXP, pzNil);
  return rx->match_s;
}

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
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(rx, va_rx, PZ_TYPE_REGEXP, 0);
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
}

/*
 * Dump
 */

int pz_dump_to_d(void *b, Id va, pz_str_d *d);

#define pz_strncat(d, s) if (!__pz_strncat(d, s)) return 0;

int __pz_strncat(pz_str_d *d, char *s) {
  size_t l = d->l + strlen(s);
  PZ_CHECK_ERROR((l + 1 > 16384), "pz_strncat: string too large", 0);
  memcpy(d->s + d->l, s, strlen(s));
  d->l += strlen(s);
  *(d->s + d->l) = 0x0;
  return 1;
}

#define pz_append_format(d, format, values...) \
  { char bs[1024]; snprintf(bs, 1023, format, values); \
  pz_strncat(d, bs); }

int pz_dump_va(void *b, Id va, pz_str_d *d) {
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
    pz_strncat(d, "(lambda ");
    Id vdecl = ca_f(a);
    pz_dump_to_d(b, vdecl, d);
    pz_strncat(d, " ");
    pz_dump_to_d(b, ca_s(a), d);
    pz_strncat(d, ")");
    return 1;
  }
  if (d->dump_debug) pz_append_format(d, "%d:", l);

  pz_strncat(d, "(");
  while ((va = pz_ary_iterate(b, a, &i)).s) {
    if (!first) { pz_strncat(d, " "); }
    pz_dump_va(b, va, d);
    first = 0;
  }
  pz_strncat(d, ")");
  return 1;
}

int pz_string_dump(void *b, Id s, pz_str_d *d) {
  char *format = ((d->dump_inspect || d->dump_debug) ?
     (PZ_TYPE(s) == PZ_TYPE_STRING ? "\"%s\"" : "'%s") :
     (PZ_TYPE(s) == PZ_TYPE_STRING ? "%s" : "%s"));
  pz_append_format(d, format, pz_string_ptr(s));
  return 1;
}

int pz_ht_dump(void *b, Id va_ht, pz_str_d *d) {
  pz_ht_iterate_t h;
  h.initialized = 0;
  pz_ht_entry_t *hr;
  if (d->dump_debug) pz_append_format(d, "%d:", pz_ht_size(b, va_ht));
  pz_strncat(d, "(#hash ");
  int first = 1;
  while ((hr = pz_ht_iterate(b, va_ht, &h))) {
    if (!first) { pz_strncat(d, " "); }
    pz_strncat(d, "(");
    pz_dump_va(b, hr->va_key, d);
    pz_strncat(d, " . ");
    pz_dump_va(b, hr->va_value, d);
    pz_strncat(d, ")");
    first = 0;
  }
  pz_strncat(d, " )");
  return 1;
}

int pz_rx_dump(void *b, Id va_rx, pz_str_d *d) {
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(rx, va_rx, PZ_TYPE_REGEXP, 0);
  pz_append_format(d, "(#/ %s)", pz_string_ptr(rx->match_s));
  return 1;
}

char* pz_special_dump(Id va) {
  if (va.s == pzTail.s) return "#tail-recursion"; 
  if (va.s == pzError.s) return "#E!";
  return "<unknown>";
}

int __pz_dump_to_d(void *b, Id va, pz_str_d *d) {
  switch (PZ_TYPE(va)) {
    case PZ_TYPE_ARRAY: return pz_ary_dump(b, va, d); break;
    case PZ_TYPE_HASH: return pz_ht_dump(b, va, d); break;
    case PZ_TYPE_HASH_PAIR: /* ignore: will always be dumped by hash */; break;
    case PZ_TYPE_REGEXP: return pz_rx_dump(b, va, d); break; 
    case PZ_TYPE_STRING: case PZ_TYPE_SYMBOL: 
        return pz_string_dump(b, va, d); break;
    case PZ_TYPE_CFUNC:
      { pz_cfunc_t *cf; PZ_TYPED_VA_TO_PTR(cf, va, PZ_TYPE_CFUNC, 0);
      if (d->dump_debug) pz_append_format(d, "cfunc:#x%lx", (long)&cf->func_ptr)
      else pz_append_format(d, "#<cfunc:%s>", pz_string_ptr(cf->name));
      return 1; break; }
    case PZ_TYPE_SPECIAL: {
        if (d->dump_debug) pz_append_format(d, "SPECIAL:#x%lx:", va.s);
        pz_strncat(d, pz_special_dump(va));
        return 1; break; }
    case PZ_TYPE_FLOAT: pz_append_format(d, "%f", PZ_FLOAT(va)); return 1; break;
    case PZ_TYPE_INT: pz_append_format(d, "%d", PZ_INT(va)); return 1; break;
    case PZ_TYPE_BOOL: {
      if (d->dump_debug) pz_append_format(d, "BOOL:%lx:", va.s); 
      pz_strncat(d, va.s ? "#t" : "#f");
      return 1; break; }
  }
  return 0;
}

int pz_dump_to_d(void *b, Id va, pz_str_d *d) {
  if (d->dump_debug) 
      pz_append_format(d, "#x%x:%s<", PZ_ADR(va), pz_type_to_cp(PZ_TYPE(va)));
  int r = __pz_dump_to_d(b, va, d);
  if (d->dump_debug) pz_strncat(d, ">");
  return r;
}

int pz_dump_to_string(void *b, Id va, char *dsc, int flags) {
  *dsc = 0x0;
  pz_str_d d;
  d.s = dsc;
  d.l = 0;
  d.dump_recurse = (flags & PZ_DUMP_RECURSE) > 0;
  d.dump_inspect = (flags & PZ_DUMP_INSPECT) > 0;
  d.dump_debug = (flags & PZ_DUMP_DEBUG) > 0;
  pz_dump_to_d(b, va, &d);
}

void pz_print_dump(void *b, Id va, int flags) {
  char dsc[16834];
  pz_dump_to_string(b, va, (char *)&dsc, flags);
  printf("%s ", dsc);
}

/*
 * deep copy
 */

Id pz_deep_copy(void *b, void *source_b, Id va_s);

Id pz_generic_deep_copy(void *b, void *source_b, Id va_s) {
  char *s; int type;
  { void *b = source_b; s = VA_TO_PTR0(va_s); P_0_R(s, pzNil); 
      type = PZ_TYPE(va_s); }
  Id va; PZ_ALLOC(va, type);
  char *p = VA_TO_PTR0(va); P_0_R(p, pzNil); 
  memcpy(p, s, PZ_CELL_SIZE);
  return va;
}

Id pz_ary_deep_copy(void *b, void *source_b, Id va_s) {
  ht_array_t *ary_s; 
  { void *b = source_b; PZ_TYPED_VA_TO_PTR(ary_s, va_s, PZ_TYPE_ARRAY, pzNil); }
  Id va_c; PZ_ALLOC(va_c, PZ_TYPE_ARRAY);
  ht_array_t *ary = VA_TO_PTR(va_c); P_0_R(ary, pzNil);
  int i = 0; 
  for (i = ary_s->start; i < ary_s->size; i++) 
      ary->va_entries[i] = pz_retain(va_c, 
      pz_deep_copy(b, source_b, ary_s->va_entries[i]));
  ary->start = ary_s->start;
  ary->size = ary_s->size;
  return va_c;
}

Id pz_ht_deep_copy(void *b, void *source_b, Id va_ht_s) {
  int k; Id va_hr_s, va_p = pzNil; pz_ht_entry_t *hr_s = &pz_ht_null_node; 
  pz_hash_t *ht_s; 
  { void *b = source_b; 
      PZ_TYPED_VA_TO_PTR(ht_s, va_ht_s, PZ_TYPE_HASH, pzNil); }
  Id h = pz_ht_new(b);
  for (k = 0; k < PZ_HT_BUCKETS; k++) {
    for (va_hr_s = ht_s->va_buckets[k]; va_hr_s.s != 0 && hr_s != NULL; 
        va_hr_s = hr_s->va_next) {
      { void *b = source_b; 
          PZ_TYPED_VA_TO_PTR(hr_s, va_hr_s, PZ_TYPE_HASH_PAIR, pzNil); }
      Id k = pz_deep_copy(b, source_b, hr_s->va_value);
      Id v = pz_deep_copy(b, source_b, hr_s->va_key); 
      pz_ht_set(b, h, k, v);
    }
  }
  return h;
}

Id pz_rx_deep_copy(void *b, void *source_b, Id va_s) {
  pz_rx_t *rx_s;
  {void *b = source_b;  
      PZ_TYPED_VA_TO_PTR(rx_s, va_s, PZ_TYPE_REGEXP, pzNil);}
  Id va_rx; PZ_ALLOC(va_rx, PZ_TYPE_REGEXP); 
  pz_rx_t *rx; PZ_TYPED_VA_TO_PTR(rx, va_rx, PZ_TYPE_REGEXP, pzNil);
  pz_zero(b, va_rx);
  rx->match_s = pz_retain(va_rx, pz_deep_copy(b, source_b, rx_s->match_s));
  return va_rx; 
}

Id pz_string_deep_copy(void *b, void *source_b, Id va_s) {
  char *s; int l, t, interned = 0;
  {void *b = source_b;  PZ_ACQUIRE_STR_D(dt, va_s, pzNil);
      l = dt.l; s = dt.s; t = PZ_TYPE(va_s); 
      interned = pz_is_interned(b, va_s); }
  Id va; PZ_ALLOC(va, PZ_TYPE_STRING);
  if (l > 0 && !pz_strdup(b, va, s, l)) return pzNil;
  PZ_TYPE(va) = t;
  return interned ? pz_intern(va) : va;
}

Id pz_deep_copy(void *b, void *source_b, Id va_s) { 
  if (!va_s.s || va_s.t.type < PZ_BASIC_TYPE_BOUNDARY) { return va_s; }; 
  switch (PZ_TYPE(va_s)) {
    case PZ_TYPE_ARRAY: return pz_ary_deep_copy(b, source_b, va_s); break;
    case PZ_TYPE_HASH: return pz_ht_deep_copy(b, source_b, va_s); break;
    case PZ_TYPE_HASH_PAIR: /* ignore: will always be copied by hash */; break;
    case PZ_TYPE_REGEXP: return pz_rx_deep_copy(b, source_b, va_s); break; 
    case PZ_TYPE_STRING: case PZ_TYPE_SYMBOL: 
        return pz_string_deep_copy(b, source_b, va_s); break;
    default: return pz_generic_deep_copy(b, source_b, va_s); break;
  }
  return pzNil;
}

int pz_register_string_ref(void *b, Id _s) {
  Id s = pz_intern(_s);
  Id v;
  if ((v = pz_ht_get(b, pz_string_refs_dict, s)).s) return PZ_INT(v);
  pz_ary_push(b, pz_string_refs, s);
  int i = pz_ary_len(b, pz_string_refs) - 1;
  pz_ht_set(b, pz_string_refs_dict, s, pz_int(i));
  return i;
}


Id pz_input(void *b, FILE *f, int interactive, char *prompt) {
  if (interactive) printf("%ld:%s", pz_active_entries(b), prompt); 
  Id cs = S("(begin");
  size_t ll; 
  char p[16384], *pp;
  int check_hashbang_first_line = !interactive;
next_line:
  pp = fgetln(f, &ll);
  size_t l = ll > 16383 ? 16383 : ll;
  memcpy(p, pp, l);
  p[l] = 0x0;
  if (l > 0 && check_hashbang_first_line && (p[0] == '#')) {
    check_hashbang_first_line = 0;
    goto next_line;
  }
  char* pi;
  if (l > 0 && (pi = index(p, ';'))) l = pi - p;
  check_hashbang_first_line = 0; 
  if (l > 0 && p[l - 1] == '\n') --l;
  Id s = pz_string_new(b, p, l);
  if (!interactive) {
    if (feof(f)) { 
      pz_string_append(b, cs, S(")"));
      return cs;
    }
    pz_string_append(b, cs, s);
    goto next_line;
  }
  //if (pz_verbose) printf("%s\n", pz_string_ptr(s));
  return s;
}

unsigned long pz_current_time_ms() {
  struct timeval now; 
  gettimeofday(&now, NULL); 
  return now.tv_sec * 1000 + (now.tv_usec / 1000);
}

#include "scheme-parser.c"

void test_atomic() {
  size_t s = 1;
  size_t n;
  size_t o, rr;
  printf("s: %ld r %ld\n", s, rr);
  rr = pz_atomic_add(&s, 10);
  printf("s: %ld r %ld\n", s, rr);
  rr = pz_atomic_inc(&s);
  printf("s: %ld r %ld\n", s, rr);

  exit(0);
}

void test_perf() {
  void *b = pz_perf;
  D("perf", pz_int(1));
  size_t c = 0;
  do {
    pz_lock_gc();
    Id h = pz_ht_new(b);
    pz_ht_set(b, h, S("k1"), S("v1"));
    pz_unlock_gc();
    pz_lock_gc();
    Id a = pz_ary_new(b);
    pz_ary_push(b, a, S("test"));
    pz_unlock_gc();
    pz_garbage_collect_full(b);
    if (c++ % 10000 == 0) { printf("%ld\n", c); }
  } while (1);
  return;
  Id s;
  {void *b = pz_perf; s = S("foo");}
  Id s2 = pz_deep_copy(b, pz_perf, s);
  D("s2", s2);
  Id h;
  {void *b = pz_perf; 
    h = pz_ht_new(b);
    pz_ht_set(b, h, S("foo"), pz_int(1));
    pz_ht_set(b, h, S("boo"), S("loo"));
  }
  Id h2 = pz_deep_copy(b, pz_perf, h);
  D("h2", h2);
  exit(0);
}

void pz_setup_perf() {
  void *b = pz_perf;
  pz_add_globals(b, pz_globals);
  pz_add_perf_symbols(b);
  FILE* fb = fopen("boot.scm", "r");
  pz_repl(b, fb, S("boot.scm"), 0);
}

int main(int argc, char **argv) {
  pz_setup();
  pz_interactive = isatty(0);
  cmd = argv[0];
  // "perf.bin"
  pz_perf_mode = strlen(cmd) > 8 && 
      (strcmp(cmd + strlen(cmd) - 8, "perf.bin") == 0);
  char *scm_filename = 0;
  if (argc > 1) { 
    scm_filename = argv[argc - 1];
    if (!pz_perf_mode) {
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
  if (!scm_filename) scm_filename = "cli.scm";
  Id fn = pz_string_append(b, S(scm_filename), S(".perf"));
  pz_perf_mc = pz_shared_memory_create(pz_string_ptr(
      pz_retain(pzNil, fn)), PZ_PERF_MEM_SIZE);
  if (pz_perf_mc) { pz_perf = pz_perf_mc->base;  }
  else { printf("failed to create perf segment!\n"); exit(1); }
  int r = pz_init_memory(pz_perf, PZ_PERF_MEM_SIZE);
  if (r == 2) exit(1);
  if (r) pz_setup_perf();
  FILE* fb = fopen("boot.scm", "r");
  pz_repl(b, fb, S("boot.scm"), 0);
  //if (pz_perf_mode) test_perf();
  debug = 1;
  pz_repl(b, fin, S(scm_filename), pz_interactive);
  return 0;
}
