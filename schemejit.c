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

#if 1
#define CDS(w, va) printf("%s %lx %x %s %s\n", w, (size_t)b, SJ_ADR(va), sj_type_to_cp(SJ_TYPE(va)), sj_string_ptr(va));
#define CDS2(w, va_h, va) printf("%s %lx %x %x %s %s\n", w, (size_t)b, SJ_ADR(va_h), SJ_ADR(va), sj_type_to_cp(SJ_TYPE(va)), sj_string_ptr(va));
#else
#define CDS(w, va) 
#define CDS2(w, va_h, va)
#endif

#define SJ_VERSION "0.0.1"
#define SJ_GC_DEBUG 

int pid;

typedef union {
  float f;
  int i;
  int address;
} sj_reg_type;

typedef union { size_t s; struct { short int type; sj_reg_type d; } t; } Id;


#define SJ_DB_MAGIC 0xF0F0
#define SJ_DB_VERSION 1

#define SJ_ADR(va) va.t.d.address
#define SJ_TYPE(va) va.t.type
#define SJ_INT(va) va.t.d.i
#define SJ_FLOAT(va) va.t.d.f

static Id sjNil = {0}; 
static Id sjTrue = {0};
static Id sjTail = {0};
static Id sjError = {0}; 

/*
 * Basic error handling
 */

typedef struct {
  char error_str[1024];
  int error_number;
} sj_error_t;

sj_error_t sj_error;
int sj_interactive = 1, sj_verbose = 1;
FILE *fin;

void sj_reset_errors() { memset(&sj_error, 0, sizeof(sj_error)); }
int sj_have_error() { return sj_error.error_str[0] != 0x0; }
#define CE(w) if (sj_have_error()) { printf("errors\n"); w; }
Id sj_handle_error_with_err_string(const char *ctx, 
    const char *error_msg, char *handle) {
  char h[1024];
  if (handle != 0)  { snprintf(h, 1023, " '%s'", handle); } 
  else { strcpy(h, ""); }
  snprintf((char *)&sj_error.error_str, 1023, "%s%s: %s", ctx, h, error_msg);
  printf("error: %s\n", sj_error.error_str);
  exit(0);
  sj_error.error_number = errno;
  return sjError;
}

Id sj_handle_error(int check, const char *ctx, char *handle) {
  if (!check) { return sjTrue; } 
  return sj_handle_error_with_err_string(ctx, strerror(errno), handle);
}

Id sj_handle_error_with_err_string_nh(const char *ctx, 
    const char *error_msg) { 
  return sj_handle_error_with_err_string(ctx, error_msg, 0);
}

/* 
 * Memory primitives 
 */

#define SJ_STATIC_ALLOC_SIZE 65536
#define SJ_VAR_COUNT 100000LL
#define SJ_MEM_SIZE (size_t)(SJ_VAR_COUNT * SJ_STATIC_ALLOC_SIZE)
#define SJ_PERF_MEM_SIZE (size_t)(1500LL * SJ_STATIC_ALLOC_SIZE)

#ifdef SJ_GC_DEBUG
typedef struct {
  const char *where;
  int line;
  int new;
  const char *retain_where;
  int retain_line;
  int retain_adr;
  size_t release_counter;
  size_t retain_counter;
} sj_var_status_t;

sj_var_status_t sj_var_status[SJ_VAR_COUNT];

void sj_register_var(Id va, const char *where, int line) {
  int adr = SJ_ADR(va);
  sj_var_status[adr].where = where;
  sj_var_status[adr].line = line;
  sj_var_status[adr].new = 1;
}
#else
#define sj_register_var(va, where, line)
#endif

void *sj_private_memory_create() {
  void *base = 0;
  base = mmap(0, SJ_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 
      -1, (off_t)0);
  if (!sj_handle_error(base == MAP_FAILED, "mmap", 0).s) return 0;
  return base;
}

typedef struct {
  int fd;
  void *base;
  char *filename;
  size_t size;
} sj_shm_t;

sj_shm_t *sj_perf_mc;

int sj_does_filename_exist(char *fn) {
  struct stat st;
  return stat(fn, &st) != -1;
}

void sj_ensure_filename(char *fn) {
  if (!sj_does_filename_exist(fn)) close(open(fn, O_CREAT, 0777)); 
}

sj_shm_t *sj_shared_memory_create(char *fn, size_t size) {
  sj_ensure_filename(fn);  
  sj_shm_t *mc = calloc(1, sizeof(sj_shm_t));
  if (!mc) {
    sj_handle_error_with_err_string_nh( __FUNCTION__, "Out of memory");
    return 0;
  }

  mc->filename = fn;
  mc->size = size;
  void *base = 0;
  if (!sj_handle_error((mc->fd = open(fn, O_RDWR, (mode_t)0777)) == -1, 
      "open", fn).s) goto open_failed;
  if (!sj_handle_error(lseek(mc->fd, mc->size - 1, SEEK_SET) == -1, 
      "lseek", fn).s) goto failed;
  if (!sj_handle_error(write(mc->fd, "", 1) != 1, "write", fn).s) goto failed;
  mc->base = mmap(0, mc->size, PROT_READ | PROT_WRITE, MAP_SHARED, mc->fd, 
      (off_t)0);
  if (!sj_handle_error(mc->base == MAP_FAILED, "mmap", fn).s) goto failed;

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
#define SJ_CELL_SIZE (SJ_STATIC_ALLOC_SIZE - RCS)

#ifdef sizeof(size_t) != 8
#error sizeof(size_t) must be 8 bytes!!
#endif

#define SJ_TYPE_BOOL 0
#define SJ_TYPE_FLOAT 1
#define SJ_TYPE_INT 2
#define SJ_TYPE_SPECIAL 3

#define sj_string_size_t short int

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
} sj_mem_descriptor_t;

typedef struct {
  int lock_pid;
  int rc_dummy; 
  Id next;
  size_t size;
} sj_mem_chunk_descriptor_t;

size_t sj_header_size() { return SJ_STATIC_ALLOC_SIZE * 4; }
Id sj_header_size_ssa() { Id a; SJ_ADR(a) = 4; return a; }
#define sj_md __sj_md(b)
void *sj_heap = 0;
void *sj_perf = 0;

sj_mem_descriptor_t *__sj_md(void *b) { return b; }


#define VA_TO_PTR0(va) \
  ((va).s ? b + RCS + ((size_t)SJ_ADR(va) * SJ_STATIC_ALLOC_SIZE) : 0) 
#define PTR_TO_VA(va, p) \
  SJ_ADR(va) = (int)(((p) - RCS - (char *)b) / SJ_STATIC_ALLOC_SIZE);

#define P_0_R(p, r) if (!(p)) { printf("From %s:%d\n", __FUNCTION__, __LINE__); return (r); }
#define P_0_R2(w, l, p, r) if (!(p)) { printf("From %s:%d\n", w, l); return (r); }
#define VA_0_R(va, r) if (!(va).s) { return (r); }
#define VA_TO_PTR(va) (__ca(b, va, __FUNCTION__, __LINE__) ? VA_TO_PTR0(va) : 0 )

int __ca(void *b, Id va, const char *where, int line) {
  char *p0 = VA_TO_PTR0(va); P_0_R(p0, 1); 
  rc_t *rc = (rc_t *)(p0 - RCS + sizeof(int));
  if ((*rc) == 0) { printf("[%s:%d] error: VA is not allocated!\n", where, line); abort(); }
  //if ((*rc) == 1) { printf("[%s:%d] Warning: RC is 0\n", where, line); abort(); }
  return 1;
}

int cnil(Id i) { return i.s == sjNil.s; }
Id cb(int i) { return i ? sjTrue : sjNil; }

#define sj_md_first_free VA_TO_PTR0((va_first = sj_md->first_free))

int sj_var_free(void *b) {
    return (sj_md->total_size - sj_md->heap_size) / SJ_STATIC_ALLOC_SIZE; }
  

#define SJ_TYPE_STRING 4
#define SJ_TYPE_SYMBOL 5
#define SJ_TYPE_CFUNC 6
#define SJ_TYPE_HASH 7
#define SJ_TYPE_HASH_PAIR 8
#define SJ_TYPE_ARRAY 9
#define SJ_TYPE_REGEXP 10
#define SJ_TYPE_MAX 10

#ifdef SJ_GC_DEBUG
Id __sj_retain(const char *where, int line, void *b, Id from, Id va);
#else
Id __sj_retain(void *b, Id va);
#endif
#define SJ_HEAP_SIZE \
    ((SJ_MEM_SIZE / SJ_STATIC_ALLOC_SIZE) * SJ_STATIC_ALLOC_SIZE)
int sj_init_memory(void *b, size_t size) {
  size_t s = size - sj_header_size();
  Id va_first;
  if (sj_md->magic != SJ_DB_MAGIC) {
    sj_md->first_free = sj_header_size_ssa();
    sj_md->total_size = s;
    sj_mem_chunk_descriptor_t *c = sj_md_first_free;
    c->next.s = 0;
    c->lock_pid = 0;
    c->size = s;

    SJ_ADR(sj_md->symbol_interns) = 1;
    SJ_TYPE(sj_md->symbol_interns) = SJ_TYPE_HASH; 
#ifdef SJ_GC_DEBUG
    __sj_retain(__FUNCTION__, __LINE__, b, sjNil, sj_md->symbol_interns);
#else
    __sj_retain(b, sj_md->symbol_interns);
#endif

    SJ_ADR(sj_md->string_interns) = 2;
    SJ_TYPE(sj_md->string_interns) = SJ_TYPE_HASH; 
#ifdef SJ_GC_DEBUG
    __sj_retain(__FUNCTION__, __LINE__, b, sjNil, sj_md->string_interns);
#else
    __sj_retain(b, sj_md->string_interns);
#endif

    SJ_ADR(sj_md->globals) = 3;
    SJ_TYPE(sj_md->globals) = SJ_TYPE_HASH; 
#ifdef SJ_GC_DEBUG
    __sj_retain(__FUNCTION__, __LINE__, b, sjNil, sj_md->globals);
#else
    __sj_retain(b, sj_md->globals);
#endif

    sj_md->magic = SJ_DB_MAGIC;
    sj_md->version = SJ_DB_VERSION;
    return 1;
  } else if (sj_md->version != SJ_DB_VERSION) {
    char es[1024]; 
    snprintf(es, 1023, "DB version is %d.  Current version is %d.", 
        sj_md->version, SJ_DB_VERSION);  
    sj_handle_error_with_err_string_nh(__FUNCTION__, es);
    return 2;
  }
  return 0;
}

char *sj_type_to_cp(short int t);

int sj_perf_mode = 0;

void sj_alloc_debug(void *b, char *p, short int type) {
  return;
  if (!sj_perf_mode || b != sj_perf) return;
  char *n = b == sj_perf ? "perf" : "scheme";
  printf("[%s:%lx] alloc %lx type: %s\n", n, (size_t)b, (size_t)p, 
      sj_type_to_cp(type));
}

inline Id sj_atomic_cas_id(volatile Id *v, Id new, Id old) {
    return (Id)sj_atomic_casq((size_t *)v, new.s, old.s); }

int sj_lock_p(char *p) { 
  //printf("lock: %lx\n", p);
retry: {}
  int *pl = (int *)p;
  int ov = *pl;
  if (ov) { 
      if (ov == pid) { printf("DEADLOCK!\n"); abort(); }
      printf("[%d] LOCK already locked: %d...\n", pid, ov); goto retry; 
  }
  int r = sj_atomic_casl(pl, pid, ov);
  if (ov = r) { printf("lock failed.. retry.\n"); goto retry; }
  return 1;
}

int sj_unlock_p(char *p) { 
  //printf("unlock: %lx\n", p);
  int *i = (int *)p; *i = 0; return 1; }

size_t sj_alloc_counter = 0;
Id sj_valloc(void *b, const char *where, short int type) {
  Id va_first;
  sj_alloc_counter++;
retry_start:
  {}
  sj_mem_chunk_descriptor_t *c = sj_md_first_free; 
  if (!c) return sj_handle_error_with_err_string_nh(where, "1: Out of memory");
  sj_lock_p((char *)c);
  Id r = { 0x0 };
  if (c->size < SJ_STATIC_ALLOC_SIZE) {
    r = sj_handle_error_with_err_string_nh(where, "2: Out of memory");
    goto finish;
  }
  if (c->size == SJ_STATIC_ALLOC_SIZE) {
    // chunk size ==  wanted size
    Id ns = sj_atomic_cas_id(&sj_md->first_free, c->next, va_first); 
    if (ns.s != va_first.s) { printf("alloc first failed\n"); goto retry; }
    PTR_TO_VA(r, (char *)c);
  } else {
    // chunk is larger than wanted 
    size_t ns, os;
    os = c->size;
    ns = sj_atomic_sub(&c->size, SJ_STATIC_ALLOC_SIZE);
    if (ns != os) { printf("alloc sub failed\n"); goto retry; }
    PTR_TO_VA(r, (char *)c + c->size);
  }
  if (!c->next.s) { sj_md->heap_size += SJ_STATIC_ALLOC_SIZE; }
  if (r.s) { 
    SJ_TYPE(r) = type; 
    char *p = VA_TO_PTR0(r);
    rc_t *rc = (rc_t *) (p - RCS + sizeof(int));
    *rc = 0x1;
    sj_alloc_debug(b, (char *)rc, type);
    short int *t = (short int *)(p - sizeof(short int));
    *t = type;
  }
finish:
  sj_unlock_p((char *) c);
  return r;

retry:
  sj_unlock_p((char *)c);
  goto retry_start;
}

int sj_zero(void *b, Id va) { 
  char *p = VA_TO_PTR0(va); P_0_R(p, 0); 
  sj_lock_p(p);
  memset(p, 0, SJ_CELL_SIZE); sj_unlock_p(p); return 1;}

#define SJ_ALLOC(va, type) va = sj_valloc(b, __FUNCTION__, type); VA_0_R(va, sjNil);
#define SJ_ALLOC2(va, type, r) va = sj_valloc(b, __FUNCTION__, type); VA_0_R(va, r);

int sj_free(void *b, Id va) {
  int t = SJ_TYPE(va);
  if (t == SJ_TYPE_BOOL || t == SJ_TYPE_FLOAT || t == SJ_TYPE_INT) return 0;
  char *used_chunk_p = VA_TO_PTR(va); P_0_R(used_chunk_p, 0);
  sj_mem_chunk_descriptor_t *mcd_used_chunk = 
      (sj_mem_chunk_descriptor_t *)used_chunk_p;
  sj_lock_p((char *)mcd_used_chunk);
  mcd_used_chunk->size = SJ_STATIC_ALLOC_SIZE;
  mcd_used_chunk->rc_dummy = 0;
  while (1) {
    Id o = mcd_used_chunk->next = sj_md->first_free;
    Id r = sj_atomic_cas_id(&sj_md->first_free, va, o);
    if (o.s == r.s) goto finish;
    printf("free failed! try again\n");
  }
finish:
  sj_unlock_p((char *)mcd_used_chunk);
  return 1;
}

/*
 * Register types.
 */

Id sj_int(int i) { 
    Id va; SJ_TYPE(va) = SJ_TYPE_INT; SJ_INT(va) = i; return va; }

Id sj_float(float f) { 
    Id va; SJ_TYPE(va) = SJ_TYPE_FLOAT; SJ_FLOAT(va) = f; return va; }

Id cn(Id v) { return SJ_TYPE(v) == SJ_TYPE_BOOL ? sj_int(v.s ? 1 : 0) : v; }

/*
 * Basic types 
 */


char *sj_types_s[] = {"nil", "float", "int", "special", "string", "symbol", "cfunc", "hash", 
    "hash pair", "array"};
char *sj_types_i[] = {"x", "f", "i", "S", "s", ":", "C", "{", "P", "["};

char *sj_type_to_cp(short int t) {
  if (t > SJ_TYPE_MAX || t < 0) { return "<unknown>"; }
  return sj_types_s[t];
}

char *sj_type_to_i_cp(short int t) {
  if (t > SJ_TYPE_MAX || t < 0) { return "?"; }
  return sj_types_i[t];
}

int sj_is_string(Id va) { 
    return SJ_TYPE(va) == SJ_TYPE_SYMBOL || SJ_TYPE(va) == SJ_TYPE_STRING; }
int sj_is_number(Id va) { 
    return SJ_TYPE(va) == SJ_TYPE_FLOAT || SJ_TYPE(va) == SJ_TYPE_INT; }
int c_type(int t) { return t == SJ_TYPE_SYMBOL ? SJ_TYPE_STRING : t;}
int sj_is_type_i(Id va, int t) { return c_type(SJ_TYPE(va)) == c_type(t); }
#define S(s) sj_string_new_c(b, s)


#define SJ_CHECK_TYPE2(w, l, va, _type, r) \
  if (!sj_is_type_i((va), (_type))) { \
    char es[1024]; \
    snprintf(es, 1023, "(%s:%d) Invalid type: Expected type '%s', " \
        "have: '%s'", \
        w, l, \
        sj_type_to_cp((_type)), sj_type_to_cp(SJ_TYPE(va)));  \
    sj_handle_error_with_err_string_nh(__FUNCTION__, es); \
    return (r); \
  }

#define SJ_CHECK_TYPE(va, _type, r) \
    SJ_CHECK_TYPE2(__FUNCTION__, __LINE__, va, _type, r)

#define SJ_CHECK_ERROR(cond,msg,r) \
  if ((cond)) { sj_handle_error_with_err_string_nh(__FUNCTION__, (msg)); return (r); }

#define __SJ_TYPED_VA_TO_PTR(ptr, va, type, r, check) \
  SJ_CHECK_TYPE((va), (type), (r)); (ptr) = check((va)); P_0_R((ptr), (r));
#define __SJ_TYPED_VA_TO_PTR2(ptr, va, type, r, check) \
  SJ_CHECK_TYPE2(w, l, (va), (type), (r)); (ptr) = check((va)); P_0_R((ptr), (r));
#define SJ_TYPED_VA_TO_PTR(p,v,t,r) __SJ_TYPED_VA_TO_PTR(p,v,t,r,VA_TO_PTR)
#define SJ_TYPED_VA_TO_PTR2(p,v,t,r) __SJ_TYPED_VA_TO_PTR2(p,v,t,r,VA_TO_PTR)
#define SJ_TYPED_VA_TO_PTR0(p,v,t,r) __SJ_TYPED_VA_TO_PTR(p,v,t,r,VA_TO_PTR0)

/*
 * Reference counting.
 */

#define RCI if (!va.s || va.t.type < 3) { return va; }; char *p0 = VA_TO_PTR0(va); \
  P_0_R(p0, sjNil); rc_t *rc = (rc_t *)(p0 - RCS + sizeof(int));

int sj_ary_free(void *b, Id);
int sj_ht_free(void *b, Id);

#define sj_release(va) __sj_release(b, va)
Id __sj_release(void *b, Id va) { 
  RCI; SJ_CHECK_ERROR((*rc <= 1), "Reference counter is already 0!", sjNil);
#ifdef SJ_GC_DEBUG
  sj_var_status[SJ_ADR(va)].release_counter++;
#endif
  --(*rc);
  return va;
}

Id sj_delete(void *b, Id va) { 
  RCI; 
  if ((*rc) == 0x0) return sjNil; // ignore, so one can jump at random address!
  SJ_CHECK_ERROR((*rc != 1), "Cannot delete, rc != 0!", sjNil);
  switch (SJ_TYPE(va)) {
    case SJ_TYPE_ARRAY: sj_ary_free(b, va); break;
    case SJ_TYPE_HASH: sj_ht_free(b, va); break;
    case SJ_TYPE_HASH_PAIR: /* ignore: will always be freed by hash */; break;
    case SJ_TYPE_REGEXP: sj_rx_free(b, va); break; 
    default: sj_free(b, va); break;
  }
  (*rc) = 0x0;
  return sjTrue;
}


size_t __sj_mem_dump(void *b, int silent) {
  size_t entries = sj_md->heap_size / SJ_STATIC_ALLOC_SIZE;
  size_t mem_start = sj_md->total_size + sj_header_size() - 
      sj_md->heap_size;
  if (!silent) printf("totalsize: %ld\n", sj_md->total_size);
  char *p = mem_start + b;
  size_t i;
  size_t active_entries = 0;
  if (!silent) printf("[%lx] mem dump: entries: %ld\n", (size_t)b, entries);
  for (i = 0; i < entries; ++i, p += SJ_STATIC_ALLOC_SIZE) {
    rc_t *rc = (rc_t *)p;
    if (*rc > 0) {
      active_entries++;
      short int *t = (short int *) (p + sizeof(int));
      Id r;
      PTR_TO_VA(r, (char *)p + RCS);
#ifdef SJ_GC_DEBUG
      sj_var_status_t *s = &sj_var_status[SJ_ADR(r)];
      if (!silent) {
        //printf("%s%x:%d%s ", sj_var_status[SJ_ADR(r)].new ? "NEW" : "",
        //SJ_ADR(r), *rc, sj_type_to_i_cp(*t));
        if (s->new) {
          printf("NEW: %x %d %s:%d %s retain from %s:%d %x %ld:%ld\n", 
              SJ_ADR(r), 
              *rc, s->where, s->line, sj_type_to_cp(*t), s->retain_where,
              s->retain_line, s->retain_adr, s->retain_counter, 
              s->release_counter);
        }
      }
      sj_var_status[SJ_ADR(r)].new = 0;
#endif
    }
  }
  //if (!silent) printf("active: %ld\n", active_entries);
  return active_entries;
}

size_t sj_mem_dump(void *b) { return __sj_mem_dump(b, 0); }
size_t sj_active_entries(void *b) { return __sj_mem_dump(b, 1); }

size_t sj_max(size_t a, size_t b) { return a > b ? a : b; }
size_t sj_min(size_t a, size_t b) { return a < b ? a : b; }

#define sj_garbage_collect(b) __sj_garbage_collect(b, 0);
#define sj_garbage_collect_full(b) __sj_garbage_collect(b, 1);
void __sj_garbage_collect(void *b, int full) {
  size_t entries = sj_md->heap_size / SJ_STATIC_ALLOC_SIZE;
  if (!full && sj_alloc_counter < 1000) entries = 10;
  else sj_alloc_counter = 0;
  size_t mem_start = sj_md->total_size + sj_header_size() - 
      sj_md->heap_size;
  char *p = mem_start + b;
  size_t i;
  for (i = 0; i < entries; ++i, p += SJ_STATIC_ALLOC_SIZE) {
    rc_t *rc = (rc_t *)p;
    short int *t = (short int *) (p + sizeof(int) + sizeof(int));
    if (*rc == 1) {
      Id va;
      PTR_TO_VA(va, p + RCS);
      SJ_TYPE(va) = *t;
      sj_delete(b, va);
    }
  }
}

#ifdef SJ_GC_DEBUG
#define sj_retain(from, va) __sj_retain(__FUNCTION__, __LINE__, b, from, va)
#define sj_retain2(from, va) __sj_retain(where, line, b, from, va)
Id __sj_retain(const char *where, int line, void *b, Id va_from, Id va) { 
#else
#define sj_retain(from, va) __sj_retain(b, va)
#define sj_retain2(from, va) __sj_retain(b, va)
Id __sj_retain(void *b, Id va) { 
#endif

  RCI;
#ifdef SJ_GC_DEBUG
  sj_var_status[SJ_ADR(va)].retain_where = where;
  sj_var_status[SJ_ADR(va)].retain_line = line;
  sj_var_status[SJ_ADR(va)].retain_adr = SJ_ADR(va_from);
  sj_var_status[SJ_ADR(va)].retain_counter++;
#endif
  (*rc)++; return va; }

/*
 * String
 */

#define SJ_STR_MAX_LEN (SJ_CELL_SIZE - sizeof(sj_string_size_t))

int sj_strdup(void *b, Id va_dest, char *source, sj_string_size_t l) {
  char *p; SJ_TYPED_VA_TO_PTR0(p, va_dest, SJ_TYPE_STRING, 0);
  SJ_CHECK_ERROR((l + 1 > SJ_STR_MAX_LEN), "strdup: string too large", 0);
  *(sj_string_size_t *) p = l;
  p += sizeof(sj_string_size_t);
  memcpy(p, source, l);
  p += l;
  (*p) = 0x0;
  return 1;
}

Id sj_string_new(void *b, char *source, sj_string_size_t l) { 
  Id va; SJ_ALLOC(va, SJ_TYPE_STRING);
  if (l > 0 && !sj_strdup(b, va, source, l)) return sjNil;
  return va;
}

Id sj_string_new_c(void *b, char *source) { 
    return sj_string_new(b, source, strlen(source)); }
#define sj_string_ptr(s) __sj_string_ptr(__FUNCTION__, __LINE__, b, s)
char *__sj_string_ptr(const char *w, int l, void *b, Id va_s);

#include "debug.c"

Id __sj_snn(void *b, Id n, const char *f) { 
  Id va; SJ_ALLOC(va, SJ_TYPE_STRING);
  int i = SJ_TYPE(n) == SJ_TYPE_INT;
  char ns[1024]; 
  i ? snprintf(ns, 1023, f, SJ_INT(n)) : 
      snprintf(ns, 1023, "%f", SJ_FLOAT(n));
  return S(ns);
}

Id sj_string_new_number(void *b, Id n) { return __sj_snn(b, n, "%d"); }
Id sj_string_new_hex_number(void *b, Id n) { return __sj_snn(b, n, "0x%x"); }

typedef struct { char *s; sj_string_size_t l; } sj_str_d;
int sr = 0;
#define SJ_ACQUIRE_STR_D(n,va,r) \
  sj_str_d n; sr = sj_acquire_string_data(b, va, &n); P_0_R(sr, r);
#define SJ_ACQUIRE_STR_D2(n,va,r) \
  sj_str_d n; sr = sj_acquire_string_data(b, va, &n); P_0_R2(w, l, sr, r);

Id sj_string_sub_str_new(void *b, Id s, int start, int _count) {
  SJ_ACQUIRE_STR_D(dt, s, sjNil);
  if (start > dt.l) start = dt.l;
  int count = (_count < 0) ? (dt.l + _count + 1) - start : _count;
  if (count < 0) count = 0;
  if (count > dt.l - start) count = dt.l - start;
  char sym[dt.l + 1];
  memcpy(&sym, dt.s + start, count);
  return sj_string_new(b, (char *)&sym, count);
}

Id sj_string_new_0(void *b) { return sj_string_new(b, "", 0); }

int sj_acquire_string_data(void *b, Id va_s, sj_str_d *d) { 
  char *s; SJ_TYPED_VA_TO_PTR(s, va_s, SJ_TYPE_STRING, 0);
  d->s = s + sizeof(sj_string_size_t); d->l = *(sj_string_size_t *) s; 
  return 1;
}

char *__sj_string_ptr(const char *w, int l, void *b, Id va_s) { 
    if (cnil(va_s)) return 0;
    SJ_ACQUIRE_STR_D2(ds, va_s, 0x0); return ds.s; }

Id sj_string_append(void *b, Id va_d, Id va_s) {
  SJ_ACQUIRE_STR_D(dd, va_d, sjNil); SJ_ACQUIRE_STR_D(ds, va_s, sjNil);
  size_t l = dd.l + ds.l;
  SJ_CHECK_ERROR((l + 1 > SJ_STR_MAX_LEN), "append: string too large", sjNil);
  memcpy(dd.s + dd.l, ds.s, ds.l);
  *(sj_string_size_t *) (dd.s - sizeof(sj_string_size_t)) = l;
  dd.s += l;
  (*dd.s) = 0x0;
  return va_d;
}

int sj_string_hash(void *b, Id va_s, size_t *hash) {
  SJ_ACQUIRE_STR_D(ds, va_s, 0); char *s = ds.s;
  size_t v;
  sj_string_size_t i;
  for (v = 0, i = 0; i++ < ds.l; s++) { v = *s + 31 * v; }
  (*hash) = v;
  return 1;
}

int sj_string_len(void *b, Id va_s) {
  SJ_ACQUIRE_STR_D(ds, va_s, 0); return ds.l; }

#define sj_string_equals_cp_i(s, sb)  \
    __sj_string_equals_cp_i(__FUNCTION__, __LINE__, b, s, sb)
int __sj_string_equals_cp_i(const char *w, int l, void *b, Id va_s, char *sb) {
  SJ_ACQUIRE_STR_D2(ds, va_s, 0); 
  size_t bl = strlen(sb);
  if (ds.l != bl) { return 0; }
  sj_string_size_t i;
  for (i = 0; i < ds.l; i++) { if (ds.s[i] != sb[i]) return 0; }
  return 1;
}

void __cp(char **d, char **s, size_t l, int is) {
    memcpy(*d, *s, l); (*d) += l; if (is) (*s) += l; }

int sj_string_starts_with(void *b, Id va_s, Id va_q) {
  SJ_ACQUIRE_STR_D(ds, va_s, 0); SJ_ACQUIRE_STR_D(dq, va_q, 0); 
  if (dq.l > ds.l) return 0;
  return strncmp(ds.s, dq.s, dq.l) == 0;
}

Id sj_string_replace(void *b, Id va_s, Id va_a, Id va_b) {
  SJ_ACQUIRE_STR_D(ds, va_s, sjNil); SJ_ACQUIRE_STR_D(da, va_a, sjNil); 
  SJ_ACQUIRE_STR_D(db, va_b, sjNil); 
  Id va_new = sj_string_new_0(b); SJ_ACQUIRE_STR_D(dn, va_new, sjNil);
  char *dp = dn.s, *sp = ds.s; P_0_R(dp, sjNil)
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
  *(sj_string_size_t *)(dn.s - sizeof(sj_string_size_t)) = dp - dn.s;
  return va_new;
}

/*
 * general var handling
 */

size_t sj_hash_var(void *b, Id va) {
  if (SJ_TYPE(va) == SJ_TYPE_STRING) {
    size_t h;
    sj_string_hash(b, va, &h);
    return h;
  }
  return va.s;
}

Id cnil2(Id i) { 
    return SJ_TYPE(i) == SJ_TYPE_ARRAY && sj_ary_len(i) == 0 ? sjNil : i; }

#define sj_equals_i(a, o) __sj_equals_i(b, a, o)
int __sj_equals_i(void *b, Id a, Id o) {
  if (SJ_TYPE(a) == SJ_TYPE_STRING && SJ_TYPE(o) == SJ_TYPE_STRING) {
     SJ_ACQUIRE_STR_D(da, a, 0); SJ_ACQUIRE_STR_D(db, o, 0); 
     if (da.l != db.l) return 0;
     sj_string_size_t i;
     for (i = 0; i < da.l; i++) {
        if (da.s[i] != db.s[i]) return 0; }
     return 1;
  } 
  return cnil2(a).s == cnil2(o).s;
}

Id sj_to_symbol(Id va_s) {
  if (SJ_TYPE(va_s) == SJ_TYPE_SYMBOL) return va_s;
  if (SJ_TYPE(va_s) != SJ_TYPE_STRING) return sjNil;
  Id s = va_s;
  SJ_TYPE(s) = SJ_TYPE_SYMBOL;
  return s;
}

/*
 * Hashtable
 */

typedef struct {
  Id va_key;
  Id va_value;
  Id va_next;
} sj_ht_entry_t;
#define SJ_HT_BUCKETS ((SJ_CELL_SIZE - (2 * sizeof(Id))) / sizeof(Id))
typedef struct {
  int size;
  Id va_buckets[SJ_HT_BUCKETS];
  Id va_parent;
} sj_hash_t;

Id sj_ht_new(void *b) {
    Id va_ht; SJ_ALLOC(va_ht, SJ_TYPE_HASH); sj_zero(b, va_ht); return va_ht; }

size_t sj_ht_hash(void *b, Id va_s) {
    return sj_hash_var(b, va_s) % SJ_HT_BUCKETS; }

sj_ht_entry_t sj_ht_null_node = { 0, 0, 0 };

#define SJ_HT_ITER_BEGIN(r) \
  Id va_hr; sj_ht_entry_t *hr = &sj_ht_null_node; \
  sj_hash_t *ht; SJ_TYPED_VA_TO_PTR(ht, va_ht, SJ_TYPE_HASH, (r)); \
  size_t k = sj_ht_hash(b, va_key); \
  for (va_hr = ht->va_buckets[k];  \
      va_hr.s != 0 && hr != NULL; ) { \
    SJ_TYPED_VA_TO_PTR(hr, va_hr, SJ_TYPE_HASH_PAIR, (r)); \
    if (!hr || !sj_equals_i(va_key, hr->va_key)) goto next; 

#define SJ_HT_ITER_END(v) } return (v);

int sj_ht_lookup(void *b, sj_ht_entry_t **_hr, Id va_ht, Id va_key) {
  (*_hr) = &sj_ht_null_node; 
  SJ_HT_ITER_BEGIN(0) 
    (*_hr) = hr;
    return 1;
    next: va_hr = hr->va_next;
  SJ_HT_ITER_END(0);
}

Id sj_ht_delete(void *b, Id va_ht, Id va_key) {
  Id va_p = sjNil;
  SJ_HT_ITER_BEGIN(sjNil);
    sj_ht_entry_t *p = VA_TO_PTR(va_p);
    if (p) { p->va_next = hr->va_next; }
    else { ht->va_buckets[k] = sjNil; }
    sj_release(hr->va_value); sj_release(hr->va_key); sj_free(b, va_hr);
    ht->size -= 1;
    return sjTrue; 
  next: va_p = va_hr;
  SJ_HT_ITER_END(sjTrue);
}

int sj_ht_free(void *b, Id va_ht) {
  int k; Id va_hr, va_p = sjNil; sj_ht_entry_t *hr = &sj_ht_null_node; 
  sj_hash_t *ht; SJ_TYPED_VA_TO_PTR(ht, va_ht, SJ_TYPE_HASH, 0); 
  for (k = 0; k < SJ_HT_BUCKETS; k++) {
    for (va_hr = ht->va_buckets[k]; va_hr.s != 0 && hr != NULL; va_hr = hr->va_next) {
      SJ_TYPED_VA_TO_PTR(hr, va_hr, SJ_TYPE_HASH_PAIR, 0); 
      sj_release(hr->va_value); sj_release(hr->va_key); 
      if (va_p.s) { sj_release(va_p); sj_free(b, va_p); }
      va_p = va_hr;
    }
  }
  if (va_p.s) { sj_release(va_p); sj_free(b, va_p); }
  sj_free(b, va_ht);
  return 1;
}

#define sj_ary_new(b) __sj_ary_new(__FUNCTION__, __LINE__, b)
Id __sj_ary_new(const char *where, int line, void *b);
#define sj_ary_push(b, var_ary, va) \
  __sj_ary_push(__FUNCTION__, __LINE__, b, var_ary, va)
Id __sj_ary_push(const char *where, int line, void *b, Id va_ary, Id va);


typedef struct {
  int initialized;
  int k;
  sj_hash_t *ht;
  Id va_hr;
  sj_ht_entry_t *hr;
} sj_ht_iterate_t;

sj_ht_entry_t *sj_ht_iterate(void *b, Id va_ht, sj_ht_iterate_t *h) {
  int new_bucket = 0;
  if (!h->initialized) {
    h->k = 0;
    h->hr = &sj_ht_null_node;
    h->va_hr = sjNil;
    SJ_TYPED_VA_TO_PTR(h->ht, va_ht, SJ_TYPE_HASH, 0); 
    h->initialized = 1;
  }
next_bucket:
  if (h->k >= SJ_HT_BUCKETS) return 0;
  if (!h->va_hr.s) { h->va_hr = h->ht->va_buckets[h->k];  new_bucket = 1;}
  if (!h->va_hr.s) { h->k++; goto next_bucket; }
  if (new_bucket) goto return_hr;
next_pair:
  h->va_hr = h->hr->va_next; 
  if (!h->va_hr.s) { h->k++; goto next_bucket; }
return_hr:
  //CDS("sjNil", sjNil);
  //CDS("va_hr", h->va_hr);
  SJ_TYPED_VA_TO_PTR(h->hr, h->va_hr, SJ_TYPE_HASH_PAIR, 0); 
  if (!h->hr) goto next_pair;
  return h->hr;
}

Id sj_ht_map(void *b, Id va_ht, Id (*func_ptr)(void *b, Id)) {
  sj_ht_iterate_t h;
  h.initialized = 0;
  sj_ht_entry_t *hr;
  Id r = sj_ary_new(b);
  while ((hr = sj_ht_iterate(b, va_ht, &h))) {
    Id s = sj_string_new_0(b);
    sj_string_append(b, s, func_ptr(b, hr->va_key));
    sj_string_append(b, s, S(" => "));
    sj_string_append(b, s, func_ptr(b, hr->va_value));
    sj_ary_push(b, r, s);
  }
  return r;
}

Id sj_ht_get(void *b, Id va_ht, Id va_key) { 
  //CDS2("get", va_ht, va_key);
  sj_ht_entry_t *hr; sj_ht_lookup(b, &hr, va_ht, va_key);  P_0_R(hr, sjNil);
  return hr->va_value;
}

#define sj_ht_set(b, va_ht, va_key, va_value) \
  __sj_ht_set(__FUNCTION__, __LINE__, b, va_ht, va_key, va_value)
Id __sj_ht_set(const char *where, int line, void *b, Id va_ht, Id va_key, 
    Id va_value) {
  //CDS2("set", va_ht, va_key);
//set_new_entry_failed:
  sj_hash_t *ht; SJ_TYPED_VA_TO_PTR(ht, va_ht, SJ_TYPE_HASH, sjNil);
  sj_ht_entry_t *hr; sj_ht_lookup(b, &hr, va_ht, va_key);
  size_t v;
  int new_entry = !hr->va_value.s;
  Id va_hr;
  if (new_entry) { 
    v = sj_ht_hash(b, va_key);
    SJ_ALLOC(va_hr, SJ_TYPE_HASH_PAIR);
    sj_register_var(va_hr, where, line);
    sj_retain2(va_ht, va_hr); hr = VA_TO_PTR(va_hr); P_0_R(hr, sjNil);
    // sj_atomic_cas
    // if it fails: go back where?
    //   -> before new entry: set_new_entry_failed
    //   -> release key!
    hr->va_key = sj_retain2(va_hr, va_key);
    // XXX sj_atomic_inc
    ht->size += 1;
  } else {
    // XXX we may release multiple times with CAS...
    // value_released = 1
    sj_release(hr->va_value);
  }

  // XXX sj_atomic_cas!
  // if it fails: retain is not valid anymore...
  //  better retain before going here..
  hr->va_value = sj_retain2(va_hr, va_value);

  if (new_entry) {
    // XXX sj_atomic_cas!
    hr->va_next = ht->va_buckets[v];
    // XXX sj_atomic_cas!
    // what if this fails and the previous succeeds?
    ht->va_buckets[v] = va_hr;
  }
  return va_value;
}

Id sj_ht_inc(void *b, Id va_ht, Id va_key) {
  Id v = sj_ht_get(b, va_ht, va_key);
  if (cnil(v)) v = sj_int(0);
  if (!sj_is_number(v)) return sjNil;
  Id vn = sj_int(SJ_INT(v) + 1);
  return sj_ht_set(b, va_ht, va_key, sj_int(SJ_INT(v) + 1));
}

#define sj_symbol_interns sj_md->symbol_interns
#define sj_string_interns sj_md->string_interns
#define sj_globals sj_md->globals

#define sj_intern(s) __sj_intern(b, s)
Id ___sj_intern(void *b, Id va_s) { 
  //if (SJ_TYPE(va_s) == SJ_TYPE_SYMBOL) SJ_TYPE(va_s) = SJ_TYPE_STRING;
  Id dict = SJ_TYPE(va_s) == SJ_TYPE_SYMBOL ? 
      sj_symbol_interns : sj_string_interns;
  Id sv = va_s; SJ_TYPE(sv) = SJ_TYPE_STRING;
  Id va = sj_ht_get(b, dict, sv); 
  if (va.s) { return va; }
  //Id va_sym = va_s; SJ_TYPE(va_sym) = SJ_TYPE_SYMBOL;
  if (cnil(sj_ht_set(b, dict, sv, va_s))) return sjNil;
  return sj_ht_get(b, dict, sv); 
}

Id __sj_intern(void *b, Id va_s) { 
  //CDS("intern <- ", va_s);
  Id r = ___sj_intern(b, va_s);
  //CDS("intern -> ", r);
  return r;
}


int sj_is_interned(void *b, Id va_s) {
  Id dict = SJ_TYPE(va_s) == SJ_TYPE_SYMBOL ? 
      sj_symbol_interns : sj_string_interns;
  Id sv = va_s; SJ_TYPE(sv) = SJ_TYPE_STRING;
  return sj_ht_get(b, dict, sv).s != 0; 
}

Id sj_env_new(void *b, Id va_ht_parent) {
  Id va = sj_ht_new(b);
  sj_hash_t *ht; SJ_TYPED_VA_TO_PTR(ht, va, SJ_TYPE_HASH, sjNil);
  ht->va_parent = va_ht_parent;
  return va;
}

#define SJ_ENV_FIND \
  Id va0 = va_ht, found = sjNil; \
  while (va_ht.s && !(found = sj_ht_get(b, va_ht, va_key)).s) { \
    sj_hash_t *ht; SJ_TYPED_VA_TO_PTR(ht, va_ht, SJ_TYPE_HASH, sjNil); \
    va_ht = ht->va_parent; \
  }

Id sj_env_find(void *b, Id va_ht, Id va_key) { 
  SJ_ENV_FIND; 
  return found; 
}

Id sj_env_find_and_set(void *b, Id va_ht, Id va_key, Id va_value) { 
  SJ_ENV_FIND;
  if (found.s) { return sj_ht_set(b, va_ht, va_key, va_value); }
  else { return sj_ht_set(b, va0, va_key, va_value); }
}

void sj_add_globals(void *b, Id env);

void sj_setup() {
  sjTrue.s = 1;
  SJ_TYPE(sjTail) = SJ_TYPE_SPECIAL;
  SJ_INT(sjTail)  = 1;
  SJ_TYPE(sjError) = SJ_TYPE_SPECIAL;
  SJ_INT(sjError)  = 2;
  pid = getpid();
}

char *cmd;

char *sj_cmd_display() { return sj_perf_mode ? "perf" : "schemejit"; }

void *sj_init(void *b, size_t size) {
#ifdef SJ_GC_DEBUG
  memset(&sj_var_status, 0, sizeof(sj_var_status));
#endif
  if (!b) return 0;
  int r = sj_init_memory(b, size);
  if (r == 2) return 0;
  if (r) sj_add_globals(b, sj_globals);
  if (sj_interactive) 
      printf("%s %s started; %d vars available\n", sj_cmd_display(), 
          SJ_VERSION, sj_var_free(b));
  return b;
}

/*
 * FFI
 */

typedef struct { Id (*func_ptr)(void *b, Id, Id); } sj_cfunc_t;

Id sj_define_func(void *b, char *name, Id (*p)(void *b, Id, Id), Id env) { 
  Id va_f; SJ_ALLOC(va_f, SJ_TYPE_CFUNC);
  sj_cfunc_t *cf; SJ_TYPED_VA_TO_PTR0(cf, va_f, SJ_TYPE_CFUNC, sjNil);
  cf->func_ptr = p;
  sj_ht_set(b, env, sj_intern(sj_to_symbol(S(name))), va_f);
  return sjTrue;
}

Id sj_call(void *b, Id va_f, Id env, Id x) { 
  sj_cfunc_t *cf; SJ_TYPED_VA_TO_PTR(cf, va_f, SJ_TYPE_CFUNC, sjNil);
  Id r = cf->func_ptr(b, env, x);
  return r;
}

/*
 * Array
 */

#define SJ_ARY_MAX_ENTRIES ((SJ_CELL_SIZE - sizeof(Id)) / sizeof(Id))
typedef struct {
  int size;
  int start; 
  int lambda;
  Id va_entries[SJ_ARY_MAX_ENTRIES];
} ht_array_t;

Id __sj_ary_new(const char *where, int line, void *b) {
  Id va_ary; SJ_ALLOC(va_ary, SJ_TYPE_ARRAY); 
  sj_register_var(va_ary, where, line);
  sj_zero(b, va_ary); return va_ary; 
}

void __ary_retain_all(void *b, Id from, ht_array_t *a) {
  int i = 0; 
  for (i = a->start; i < a->size; i++) sj_retain(from, a->va_entries[i]);
}

#define sj_ary_clone(b, va_s) __sj_ary_clone(b, va_s, -1, -1)
#define sj_ary_clone_part(b, va_s, s, c) __sj_ary_clone(b, va_s, s, c)
Id __sj_ary_clone(void *b, Id va_s, int start, int count) {
  ht_array_t *ary_s; SJ_TYPED_VA_TO_PTR(ary_s, va_s, SJ_TYPE_ARRAY, sjNil);
  Id va_c; SJ_ALLOC(va_c, SJ_TYPE_ARRAY);
  char *p_c = VA_TO_PTR(va_c), *p_s = VA_TO_PTR(va_s);
  memcpy(p_c, p_s, SJ_CELL_SIZE);
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

int sj_ary_free(void *b, Id va_ary) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, 0);
  int i = 0;
  for (i = ary->start; i < ary->size; i++) sj_release(ary->va_entries[i]);
  sj_free(b, va_ary);
  return 1;
}

Id sj_ary_new_join(void *b, Id a, Id o) {
  ht_array_t *aa; SJ_TYPED_VA_TO_PTR(aa, a, SJ_TYPE_ARRAY, sjNil);
  ht_array_t *ab; SJ_TYPED_VA_TO_PTR(ab, o, SJ_TYPE_ARRAY, sjNil);
  Id n; SJ_ALLOC(n, SJ_TYPE_ARRAY);
  ht_array_t *an; SJ_TYPED_VA_TO_PTR(an, n, SJ_TYPE_ARRAY, sjNil);
  int aas = aa->size - aa->start;
  an->size = aas + ab->size - ab->start;
  SJ_CHECK_ERROR((an->size >= SJ_ARY_MAX_ENTRIES), "array is full", sjNil);
  memcpy(&an->va_entries, &aa->va_entries + aa->start, aas * sizeof(Id));
  memcpy(&an->va_entries[aas + 1], &ab->va_entries + ab->start, 
      (ab->size - ab->start) * sizeof(Id));
  __ary_retain_all(b, n, an);
  return n;
}

Id sj_ary_join_by_s(void *b, Id va_ary, Id va_js) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, sjNil);
  SJ_ACQUIRE_STR_D(djs, va_js, sjNil);
  char rs[SJ_CELL_SIZE];
  sj_string_size_t ts = 0;
  int i;
  for (i = ary->start; i < ary->size; i++) {
    Id va_s = ary->va_entries[i];
    SJ_ACQUIRE_STR_D(ds, va_s, sjNil);
    SJ_CHECK_ERROR((ts + ds.l + djs.l >= SJ_CELL_SIZE),"join: array too large",sjNil);
    memcpy(rs + ts, ds.s, ds.l);
    ts += ds.l;
    memcpy(rs + ts, djs.s, djs.l);
    ts += djs.l;
  }
  Id va_n = sj_string_new(b, rs, ts ? ts - djs.l : ts);
  return va_n;
}

Id __sj_ary_push(const char *where, int line, void *b, Id va_ary, Id va) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, sjNil);
  SJ_CHECK_ERROR((ary->size >= SJ_ARY_MAX_ENTRIES), "array is full", sjNil);
  ary->size += 1;
  ary->va_entries[ary->start + ary->size - 1] = sj_retain2(va_ary, va);
  return va_ary;
}

int sj_ary_set_lambda(void *b, Id va_ary) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, 0);
  ary->lambda = 1;
  return 1;
}

int sj_ary_is_lambda(void *b, Id va_ary) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, 0);
  return ary->lambda;
}


Id sj_ary_map(void *b, Id va_ary, Id (*func_ptr)(void *b, Id)) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, sjNil);
  int i;
  Id r = sj_ary_new(b);
  for (i = ary->start; i < ary->size; i++) 
      sj_ary_push(b, r, func_ptr(b, ary->va_entries[i]));
  return r;
}

Id sj_ary_unshift(void *b, Id va_ary) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, sjNil);
  if (ary->size - ary->start <= 0) { return sjNil; } 
  ary->start++;
  return sj_release(ary->va_entries[ary->start - 1]);
}

Id sj_ary_set(void *b, Id va_ary, int i, Id va) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, sjNil);
  SJ_CHECK_ERROR((ary->start + i >= SJ_ARY_MAX_ENTRIES), 
      "array index too large", sjNil);
  if (i - ary->start > ary->size) ary->size = i - ary->start;
  Id va_o = ary->va_entries[ary->start + i];
  if (va_o.s) sj_release(va_o);
  // XXX sj_atomic_cas
  ary->va_entries[ary->start + i] = va;
  return va;
}

Id sj_ary_pop(void *b, Id va_ary) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, sjNil);
  if (ary->size - ary->start <= 0) { return sjNil; } 
  ary->size--;
  return sj_release(ary->va_entries[ary->start + ary->size]);
}

int sj_ary_len(void *b, Id va_ary) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, -1);
  return ary->size - ary->start;
}

Id sj_ary_index(void *b, Id va_ary, int i) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR(ary, va_ary, SJ_TYPE_ARRAY, sjNil);
  if (i < 0) i = ary->size - ary->start + i;
  if (ary->size - ary->start < i) { return sjNil; } 
  return ary->va_entries[ary->start + i];
}

Id ca_i(void *b, Id va_ary, int i) { return sj_ary_index(b, va_ary, i); }
#define ca_f(ary) ca_i(b, ary, 0)
#define ca_s(ary) ca_i(b, ary, 1)
#define ca_th(ary) ca_i(b, ary, 2)
#define ca_fth(ary) ca_i(b, ary, 3)

#define sj_ary_iterate(b, va_ary, i) \
  __sj_ary_iterate(__FUNCTION__, __LINE__, b, va_ary, i)
Id __sj_ary_iterate(const char *w, int l, void *b, Id va_ary, int *i) {
  ht_array_t *ary; SJ_TYPED_VA_TO_PTR2(ary, va_ary, SJ_TYPE_ARRAY, sjNil);
  if (*i >= ary->size - ary->start) { return sjNil; }
  return sj_ary_index(b, va_ary, (*i)++); 
}

int sj_ary_contains_only_type_i(void *b, Id a, int t) {
  int i = 0; Id va;
  while ((va = sj_ary_iterate(b, a, &i)).s)
      if (!sj_is_type_i(va, t))  return 0;
  return 1;
}

#define SJ_PUSH_STRING { \
    int l = ds.s + i - last_start - match_pos; \
    if (l > 0) { \
      Id va_ns = sj_string_new(b, last_start, l); VA_0_R(va_ns, sjNil); \
      if (!sj_ary_push(b, va_ary, va_ns).s) return sjNil; }}

Id sj_string_split(void *b, Id va_s, char sep) {
  Id va_ary = sj_ary_new(b);
  SJ_ACQUIRE_STR_D(ds, va_s, sjNil);
  if (ds.l == 0) return sjNil;
  size_t i, match_pos = 0;
  char *last_start = ds.s;

  for (i = 0; i < ds.l; i++) {
    if (ds.s[i] != sep) {
      if (match_pos > 0) {
        SJ_PUSH_STRING;
        last_start = ds.s + i;
        match_pos = 0;
      }
      continue;
    }
    match_pos++;
  }
  SJ_PUSH_STRING;
  return va_ary;
}

Id sj_string_split2(void *b, Id va_s, Id sep) {
  SJ_ACQUIRE_STR_D(ds, sep, sjNil);
  if (ds.l == 0) return sjNil;
  return sj_string_split(b, va_s, ds.s[0]);
}

/*
 * regular expressions
 *
 * Implementation heavily borrows from Rob Pike's regexp implementation,
 * as described here:
 *
 * http://www.cs.princeton.edu/courses/archive/spr09/cos333/beautiful.html
 */

#define SJ_ARY_MAX_ENTRIES ((SJ_CELL_SIZE - sizeof(Id)) / sizeof(Id))
typedef struct {
  Id match_s;
} sj_rx_t;

#define sj_rx_new(match_s) __sj_rx_new(__FUNCTION__, __LINE__, b, match_s);
Id __sj_rx_new(const char *where, int line, void *b, Id match_s) {
  Id va_rx; SJ_ALLOC(va_rx, SJ_TYPE_REGEXP); 
  sj_rx_t *rx; SJ_TYPED_VA_TO_PTR(rx, va_rx, SJ_TYPE_REGEXP, sjNil);
  sj_zero(b, va_rx);
  rx->match_s = sj_retain2(va_rx, match_s);
  sj_register_var(va_rx, where, line);
  return va_rx; 
}

int sj_rx_free(void *b, Id va_rx) {
  sj_rx_t *rx; SJ_TYPED_VA_TO_PTR(rx, va_rx, SJ_TYPE_REGEXP, 0);
  sj_release(rx->match_s);
  return 1;
}

Id sj_rx_match_string(void *b, Id va_rx) {
  sj_rx_t *rx; SJ_TYPED_VA_TO_PTR(rx, va_rx, SJ_TYPE_REGEXP, sjNil);
  return rx->match_s;
}

int __sj_rx_matchstar(int c, char *ms, int ml, char *s, int sl) {
  do {
    if (__sj_rx_matchhere(ms, ml, s, sl)) return 1;
    if (sl < 1) return 0;
    if (c != '.' && (sl < 1 || s[0] != c)) return 0;
    sl--;
    s++;
  } while (1);
}

int __sj_rx_matchhere(char *ms, int ml, char *s, int sl) {
  if (ml < 1) return 1;
  if (ml > 1 && ms[1] == '*')
    return __sj_rx_matchstar(ms[0], ms + 2, ml - 2, s, sl);
  if (ms[0] == '$' && ml == 1)
    return sl == 0;   
  if (sl > 0 && (ms[0] == '.' || ms[0] == s[0])) 
    return __sj_rx_matchhere(ms + 1, ml - 1, s + 1, sl - 1);
  return 0;
}

int sj_rx_match(void *b, Id va_rx, Id va_s) {
  sj_rx_t *rx; SJ_TYPED_VA_TO_PTR(rx, va_rx, SJ_TYPE_REGEXP, 0);
  SJ_ACQUIRE_STR_D(ms, rx->match_s, 0);
  SJ_ACQUIRE_STR_D(s, va_s, 0);
  if (!ms.l) return 0;
  if (ms.s[0] == '^')
      return __sj_rx_matchhere(ms.s + 1, ms.l - 1, s.s, s.l);
  do {
    if (__sj_rx_matchhere(ms.s, ms.l, s.s, s.l)) return 1;
    s.s++;
    s.l--;
  } while (s.l > 0);
}

/*
 * deep copy
 */

Id sj_deep_copy(void *b, void *source_b, Id va_s);

Id sj_generic_deep_copy(void *b, void *source_b, Id va_s) {
  char *s; int type;
  { void *b = source_b; s = VA_TO_PTR0(va_s); P_0_R(s, sjNil); 
      type = SJ_TYPE(va_s); }
  Id va; SJ_ALLOC(va, type);
  char *p = VA_TO_PTR0(va); P_0_R(p, sjNil); 
  memcpy(p, s, SJ_CELL_SIZE);
  return va;
}

Id sj_ary_deep_copy(void *b, void *source_b, Id va_s) {
  ht_array_t *ary_s; 
  { void *b = source_b; SJ_TYPED_VA_TO_PTR(ary_s, va_s, SJ_TYPE_ARRAY, sjNil); }
  Id va_c; SJ_ALLOC(va_c, SJ_TYPE_ARRAY);
  ht_array_t *ary = VA_TO_PTR(va_c); P_0_R(ary, sjNil);
  int i = 0; 
  for (i = ary_s->start; i < ary_s->size; i++) 
      ary->va_entries[i] = sj_retain(va_c, 
      sj_deep_copy(b, source_b, ary_s->va_entries[i]));
  ary->start = ary_s->start;
  ary->size = ary_s->size;
  return va_c;
}

Id sj_ht_deep_copy(void *b, void *source_b, Id va_ht_s) {
  int k; Id va_hr_s, va_p = sjNil; sj_ht_entry_t *hr_s = &sj_ht_null_node; 
  sj_hash_t *ht_s; 
  { void *b = source_b; 
      SJ_TYPED_VA_TO_PTR(ht_s, va_ht_s, SJ_TYPE_HASH, sjNil); }
  Id h = sj_ht_new(b);
  for (k = 0; k < SJ_HT_BUCKETS; k++) {
    for (va_hr_s = ht_s->va_buckets[k]; va_hr_s.s != 0 && hr_s != NULL; 
        va_hr_s = hr_s->va_next) {
      { void *b = source_b; 
          SJ_TYPED_VA_TO_PTR(hr_s, va_hr_s, SJ_TYPE_HASH_PAIR, sjNil); }
      Id k = sj_deep_copy(b, source_b, hr_s->va_value);
      Id v = sj_deep_copy(b, source_b, hr_s->va_key); 
      sj_ht_set(b, h, k, v);
    }
  }
  return h;
}

Id sj_rx_deep_copy(void *b, void *source_b, Id va_s) {
  sj_rx_t *rx_s;
  {void *b = source_b;  
      SJ_TYPED_VA_TO_PTR(rx_s, va_s, SJ_TYPE_REGEXP, sjNil);}
  Id va_rx; SJ_ALLOC(va_rx, SJ_TYPE_REGEXP); 
  sj_rx_t *rx; SJ_TYPED_VA_TO_PTR(rx, va_rx, SJ_TYPE_REGEXP, sjNil);
  sj_zero(b, va_rx);
  rx->match_s = sj_retain(va_rx, sj_deep_copy(b, source_b, rx_s->match_s));
  return va_rx; 
}

Id sj_string_deep_copy(void *b, void *source_b, Id va_s) {
  char *s; int l, t, interned = 0;
  {void *b = source_b;  SJ_ACQUIRE_STR_D(dt, va_s, sjNil);
      l = dt.l; s = dt.s; t = SJ_TYPE(va_s); 
      interned = sj_is_interned(b, va_s); }
  Id va; SJ_ALLOC(va, SJ_TYPE_STRING);
  if (l > 0 && !sj_strdup(b, va, s, l)) return sjNil;
  SJ_TYPE(va) = t;
  return interned ? sj_intern(va) : va;
}

Id sj_deep_copy(void *b, void *source_b, Id va_s) { 
  if (!va_s.s || va_s.t.type < 3) { return va_s; }; 
  switch (SJ_TYPE(va_s)) {
    case SJ_TYPE_ARRAY: return sj_ary_deep_copy(b, source_b, va_s); break;
    case SJ_TYPE_HASH: return sj_ht_deep_copy(b, source_b, va_s); break;
    case SJ_TYPE_HASH_PAIR: /* ignore: will always be copied by hash */; break;
    case SJ_TYPE_REGEXP: return sj_rx_deep_copy(b, source_b, va_s); break; 
    case SJ_TYPE_STRING: case SJ_TYPE_SYMBOL: 
        return sj_string_deep_copy(b, source_b, va_s); break;
    default: return sj_generic_deep_copy(b, source_b, va_s); break;
  }
  return sjNil;
}


Id sj_input(void *b, FILE *f, int interactive, char *prompt) {
  if (interactive) printf("%ld:%s", sj_active_entries(b), prompt); 
  Id cs = S("(begin");
  size_t l; 
  char *p;
next_line:
  p = fgetln(f, &l);
  if (l > 0 && (p[0] == ';' || p[0] == '#')) {
    if (interactive) return sjNil;
    else goto next_line;
  }
  if (l > 0 && p[l - 1] == '\n') --l;
  Id s = sj_string_new(b, p, l);
  if (!interactive) {
    if (feof(f)) { 
      sj_string_append(b, cs, S(")"));
      return cs;
    }
    sj_string_append(b, cs, s);
    goto next_line;
  }
  //if (sj_verbose) printf("%s\n", sj_string_ptr(s));
  return s;
}

unsigned long sj_current_time_ms() {
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
  rr = sj_atomic_add(&s, 10);
  printf("s: %ld r %ld\n", s, rr);
  rr = sj_atomic_inc(&s);
  printf("s: %ld r %ld\n", s, rr);

  exit(0);
}

void test_perf() {
  void *b = sj_perf;
  D("perf", sj_int(1));
  do {
    Id h = sj_ht_new(b);
    //sj_ht_free(b, h);
    sj_ht_free(b, h);
    //Id k = S("key"), v = S("value");
    ////sj_ht_set(b, h, k, v);
    ////sj_ht_free(b, h);
    //sj_free(b, k);
    //sj_free(b, v);
  } while (1);
  return;
  Id s;
  {void *b = sj_perf; s = S("foo");}
  Id s2 = sj_deep_copy(b, sj_perf, s);
  D("s2", s2);
  Id h;
  {void *b = sj_perf; 
    h = sj_ht_new(b);
    sj_ht_set(b, h, S("foo"), sj_int(1));
    sj_ht_set(b, h, S("boo"), S("loo"));
  }
  Id h2 = sj_deep_copy(b, sj_perf, h);
  D("h2", h2);
  exit(0);
}

void sj_setup_perf() {
  void *b = sj_perf;
  sj_add_globals(b, sj_globals);
  sj_add_perf_symbols(b);
  FILE* fb = fopen("boot.scm", "r");
  sj_repl(b, fb, S("boot.scm"), 0);
}

int main(int argc, char **argv) {
  sj_setup();
  sj_interactive = isatty(0);
  cmd = argv[0];
  // "perf.bin"
  sj_perf_mode = strlen(cmd) > 8 && 
      (strcmp(cmd + strlen(cmd) - 8, "perf.bin") == 0);
  char *scm_filename = 0;
  if (argc > 1) { 
    scm_filename = argv[argc - 1];
    if (!sj_perf_mode) {
      if ((fin = fopen(scm_filename, "r")) == NULL) {
          perror(argv[argc - 1]); exit(1); }
      sj_interactive = 0;
      sj_verbose = argc > 2;
    } else {
      fin = stdin;
    }
  } else { fin = stdin; }
  sj_heap = sj_init(sj_private_memory_create(), SJ_HEAP_SIZE);
  if (!sj_heap) exit(1);
  void *b = sj_heap;
  if (!scm_filename) scm_filename = "cli.scm";
  Id fn = sj_string_append(b, S(scm_filename), S(".perf"));
  sj_perf_mc = sj_shared_memory_create(sj_string_ptr(
      sj_retain(sjNil, fn)), SJ_PERF_MEM_SIZE);
  if (sj_perf_mc) { sj_perf = sj_perf_mc->base;  }
  else { printf("failed to create perf segment!\n"); exit(1); }
  int r = sj_init_memory(sj_perf, SJ_PERF_MEM_SIZE);
  if (r == 2) exit(1);
  if (r) sj_setup_perf();
  FILE* fb = fopen("boot.scm", "r");
  sj_repl(b, fb, S("boot.scm"), 0);
  if (sj_perf_mode) test_perf();
  sj_repl(b, fin, S(scm_filename), sj_interactive);
  return 0;
}
