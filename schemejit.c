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

#define CL_VERSION "0.0.1"

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

#define CL_MEM_SIZE (size_t)(70LL * 1024 * 1024 * 1024)

void *cl_shm_create() {
  void *base = 0;
  base = mmap(0, CL_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, 
      -1, (off_t)0);
  if (!cl_handle_error(base == MAP_FAILED, "mmap", 0).s) return 0;
  return base;
}

/* 
 * Memory management
 */

#define CL_STATIC_ALLOC_SIZE 65535
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

#define cl_string_size_t short int

typedef struct {
  int rc_dummy;  
  Id first_free;
  size_t heap_size;
  size_t total_size;
} cl_mem_descriptor_t;

typedef struct {
  int rc_dummy; 
  Id next;
  size_t size;
} cl_mem_chunk_descriptor_t;

size_t cl_header_size() { return CL_STATIC_ALLOC_SIZE; }
Id cl_header_size_ssa() { Id a; CL_ADR(a) = 1; return a; }
#define cl_md __cl_md(b)
void *cl_heap;
void *cl_perf;

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
  

#define CL_HEAP_SIZE \
    ((CL_MEM_SIZE / CL_STATIC_ALLOC_SIZE) * CL_STATIC_ALLOC_SIZE)
void cl_init_memory(void *b, size_t size) {
  size_t s = size - cl_header_size();
  cl_md->first_free = cl_header_size_ssa();
  cl_md->total_size = s;
  cl_mem_chunk_descriptor_t *c = cl_md_first_free(b);
  c->next.s = 0;
  c->size = s;
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

#define CL_TYPE_STRING 3
#define CL_TYPE_SYMBOL 4
#define CL_TYPE_CFUNC 5
#define CL_TYPE_HASH 6
#define CL_TYPE_HASH_PAIR 7
#define CL_TYPE_ARRAY 8
#define CL_TYPE_MAX 8

char *cl_types_s[] = {"nil", "float", "int", "string", "symbol", "cfunc", "hash", 
    "hash pair", "array"};
char *cl_types_i[] = {"", "", "", "'", ":", "", "%", "", ""};

char *cl_type_to_cp(short int t) {
  if (t > CL_TYPE_MAX || t < 0) { return "<unknown>"; }
  return cl_types_s[t];
}

char *cl_type_to_i_cp(short int t) {
  if (t > CL_TYPE_MAX || t < 0) { return "<unknown>"; }
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

Id cl_release(void *b, Id va) { 
  RCI; CL_CHECK_ERROR((*rc <= 1), "Reference counter is already 0!", clNil);
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

void cl_garbage_collect(void *b) {
  size_t entries = cl_md->heap_size / CL_STATIC_ALLOC_SIZE;
  size_t mem_start = cl_md->total_size + cl_header_size() - 
      cl_md->heap_size;
  char *p = mem_start + b;
  size_t i;
  for (i = 0; i < entries; ++i, p += CL_STATIC_ALLOC_SIZE) {
    rc_t *rc = (rc_t *)p;
    short int *t = (short int *) (p + sizeof(int));
    if (*rc == 1) {
      Id va;
      PTR_TO_VA(va, p + RCS);
      CL_TYPE(va) = *t;
      cl_delete(b, va);
    }
  }
}

Id cl_retain(void *b, Id va) { RCI; (*rc)++; return va; }

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
#include "debug.c"


Id cl_string_new_number(void *b, Id n) { 
  Id va; CL_ALLOC(va, CL_TYPE_STRING);
  int i = CL_TYPE(n) == CL_TYPE_INT;
  char ns[1024]; 
  i ? snprintf(ns, 1023, "%d", CL_INT(n)) : 
      snprintf(ns, 1023, "%f", CL_FLOAT(n));
  return S(ns);
}

Id cl_string_new_0(void *b) { return cl_string_new(b, "", 0); }

typedef struct { char *s; cl_string_size_t l; } cl_str_d;

int cl_acquire_string_data(void *b, Id va_s, cl_str_d *d) { 
  char *s; CL_TYPED_VA_TO_PTR(s, va_s, CL_TYPE_STRING, 0);
  d->s = s + sizeof(cl_string_size_t); d->l = *(cl_string_size_t *) s; 
  return 1;
}

int sr = 0;
#define CL_ACQUIRE_STR_D(n,va,r) \
  cl_str_d n; sr = cl_acquire_string_data(b, va, &n); P_0_R(sr, r);
#define CL_ACQUIRE_STR_D2(w,l, n,va,r) \
  cl_str_d n; sr = cl_acquire_string_data(b, va, &n); P_0_R2(w, l, sr, r);
char *cl_string_ptr(void *b, Id va_s) { 
    CL_ACQUIRE_STR_D(ds, va_s, 0x0); return ds.s; }

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
    __cl_string_equals_cp_i(b, __FUNCTION__, __LINE__, s, sb)
int __cl_string_equals_cp_i(void *b, const char *w, int l, Id va_s, char *sb) {
  CL_ACQUIRE_STR_D2(w, l, ds, va_s, 0); 
  size_t bl = strlen(sb);
  if (ds.l != bl) { return 0; }
  cl_string_size_t i;
  for (i = 0; i < ds.l; i++) { if (ds.s[i] != sb[i]) return 0; }
  return 1;
}

void __cp(char **d, char **s, size_t l, int is) {
    memcpy(*d, *s, l); (*d) += l; if (is) (*s) += l; }

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

int cl_ht_hash_destroy(Id ht) { 
  return 1;
}

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
    cl_release(b, hr->va_value); cl_release(b, hr->va_key); cl_free(b, va_hr);
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
      cl_release(b, hr->va_value); cl_release(b, hr->va_key); 
      if (va_p.s) cl_free(b, va_p);
      va_p = va_hr;
    }
  }
  if (va_p.s) cl_free(b, va_p);
  cl_free(b, va_ht);
  return 1;
}

Id cl_ht_get(void *b, Id va_ht, Id va_key) { 
  cl_ht_entry_t *hr; cl_ht_lookup(b, &hr, va_ht, va_key);  P_0_R(hr, clNil);
  return hr->va_value;
}

Id cl_ht_set(void *b, Id va_ht, Id va_key, Id va_value) {
  cl_hash_t *ht; CL_TYPED_VA_TO_PTR(ht, va_ht, CL_TYPE_HASH, clNil);
  cl_ht_entry_t *hr; cl_ht_lookup(b, &hr, va_ht, va_key);
  size_t v;
  int new_entry = !hr->va_value.s;
  Id va_hr;
  if (new_entry) { 
    v = cl_ht_hash(b, va_key);
    CL_ALLOC(va_hr, CL_TYPE_HASH_PAIR);
    cl_retain(b, va_hr); hr = VA_TO_PTR(va_hr); P_0_R(hr, clNil);
    hr->va_key = cl_retain(b, va_key);
    ht->size += 1;
  } 

  hr->va_value = cl_retain(b, va_value);
  if (new_entry) {
    hr->va_next = ht->va_buckets[v];
    ht->va_buckets[v] = va_hr;
  }
  return va_value;
}

Id cl_symbols;

Id cl_intern(void *b, Id va_s) { 
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

Id cl_global_env;

void cl_add_globals(void *b, Id env);

void cl_setup() {
  clTrue.t.d.i = 1;
  clTail.t.d.i = 2;
}

void *cl_init(void *b, size_t size) {
  cl_init_memory(b, size);
  cl_symbols = cl_retain(b, cl_ht_new(b));
  cl_global_env = cl_retain(b, cl_ht_new(b));
  cl_add_globals(b, cl_global_env);
  if (cl_interactive) 
      printf("schemejit %s started; %d vars available\n", CL_VERSION, 
      cl_var_free(b));
  return b;
}

/*
 * FFI
 */

typedef struct { Id (*func_ptr)(void *b, Id); } cl_cfunc_t;

Id cl_define_func(void *b, char *name, Id (*p)(void *b, Id), Id env) { 
  Id va_f; CL_ALLOC(va_f, CL_TYPE_CFUNC);
  cl_cfunc_t *cf; CL_TYPED_VA_TO_PTR0(cf, va_f, CL_TYPE_CFUNC, clNil);
  cf->func_ptr = p;
  cl_ht_set(b, env, cl_intern(b, S(name)), va_f);
  return clTrue;
}

Id cl_call(void *b, Id va_f, Id x) { 
  cl_cfunc_t *cf; CL_TYPED_VA_TO_PTR(cf, va_f, CL_TYPE_CFUNC, clNil);
  return cf->func_ptr(b, x);
}

/*
 * Array
 */

#define CL_ARY_MAX_ENTRIES ((CL_CELL_SIZE - sizeof(Id)) / sizeof(Id))
typedef struct {
  int size;
  int start; 
  Id va_entries[CL_ARY_MAX_ENTRIES];
} ht_array_t;

Id cl_ary_new(void *b) {
  Id va_ary; CL_ALLOC(va_ary, CL_TYPE_ARRAY); 
  cl_zero(b, va_ary); return va_ary; 
}

void __ary_retain_all(void *b, ht_array_t *a) {
    int i = 0; for (i = a->start; i < a->size; i++) cl_retain(b, a->va_entries[i]);}

Id cl_ary_clone(void *b, Id va_s) {
  ht_array_t *ary_s; CL_TYPED_VA_TO_PTR(ary_s, va_s, CL_TYPE_ARRAY, clNil);
  Id va_c; CL_ALLOC(va_c, CL_TYPE_ARRAY);
  char *p_c = VA_TO_PTR(va_c), *p_s = VA_TO_PTR(va_s);
  memcpy(p_c, p_s, CL_CELL_SIZE);
  __ary_retain_all(b, (ht_array_t *)p_c);
  return va_c;
}

int cl_ary_free(void *b, Id va_ary) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, 0);
  int i = 0;
  for (i = ary->start; i < ary->size; i++) cl_release(b, ary->va_entries[i]);
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
  __ary_retain_all(b, an);
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

Id cl_ary_map(void *b, Id va_ary, Id (*func_ptr)(void *b, Id)) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  int i;
  Id r = cl_ary_new(b);
  for (i = ary->start; i < ary->size; i++) 
      cl_ary_push(b, r, func_ptr(b, ary->va_entries[i]));
  return r;
}

int cl_ary_push(void *b, Id va_ary, Id va) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, 0);
  CL_CHECK_ERROR((ary->size >= CL_ARY_MAX_ENTRIES), "array is full", 0);
  ary->size += 1;
  ary->va_entries[ary->start + ary->size - 1] = cl_retain(b, va);
  return 1;
}

Id cl_ary_unshift(void *b, Id va_ary) {
  ht_array_t *ary; CL_TYPED_VA_TO_PTR(ary, va_ary, CL_TYPE_ARRAY, clNil);
  if (ary->size - ary->start <= 0) { return clNil; } 
  ary->start++;
  return cl_release(b, ary->va_entries[ary->start - 1]);
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
      if (!cl_ary_push(b, va_ary, va_ns)) return clNil; }}

Id cl_string_split(void *b, Id va_s) {
  Id va_ary = cl_ary_new(b);
  CL_ACQUIRE_STR_D(ds, va_s, clNil);
  if (ds.l == 0) return clNil;
  size_t i, match_pos = 0;
  char *last_start = ds.s;

  for (i = 0; i < ds.l; i++) {
    if (ds.s[i] != ' ') {
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

Id cl_input(void *b, FILE *f, int interactive, char *prompt) {
  if (interactive) printf("%s", prompt); 
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
  if (cl_verbose) printf("%s\n", cl_string_ptr(b, s));
  return s;
}

unsigned long cl_current_time_ms() {
  struct timeval now; 
  gettimeofday(&now, NULL); 
  return now.tv_sec * 1000 + (now.tv_usec / 1000);
}

#include "scheme-parser.c"

int main(int argc, char **argv) {
  cl_setup();
  cl_interactive = isatty(0);
  if (argc > 1) { 
    if ((fin = fopen(argv[argc - 1], "r")) == NULL) {
        perror(argv[argc - 1]); exit(1); }
    cl_interactive = 0;
    cl_verbose = argc > 2;
  } else { fin = stdin; }
  cl_heap = cl_init(cl_shm_create(), CL_HEAP_SIZE);
  FILE* fb = fopen("boot.scm", "r");
  cl_repl(cl_heap, fb, 0);
  cl_repl(cl_heap, fin, cl_interactive);
  return 0;
}

