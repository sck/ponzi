inline size_t pz_atomic_casq(volatile size_t *v, size_t _new, size_t old) {
  size_t before;
  __asm__ __volatile__("lock; cmpxchgq %1,%2"
      : "=a" (before)
      : "q" (_new), "m"(*(volatile long long*)(v)), "0" (old)
      : "memory");
  return before;
}

inline int pz_atomic_casl(volatile int *v, int _new, int old) {
  int before;
  __asm__ __volatile__("lock; cmpxchgl %1,%2"
      : "=a" (before)
      : "q" (_new), "m"(*(volatile long long*)(v)), "0" (old)
      : "memory");
  return before;
}


inline size_t pz_atomic_add(size_t* v, size_t add)
{
  __asm__ __volatile__("lock xadd %0,%1"
               : "=r" (add), "=m" (*v)
               : "0" (add)
               : "memory");
  return add;
}

inline size_t pz_atomic_sub(size_t* v, size_t sub) { 
    return pz_atomic_add(v, -sub); }

size_t pz_atomic_inc(size_t* v) { return pz_atomic_add(v, 1); }

inline size_t pz_atomic_addl(int* v, int add)
{
  __asm__ __volatile__("lock xaddl %0,%1"
               : "=r" (add), "=m" (*v)
               : "0" (add)
               : "memory");
  return add;
}

inline size_t pz_atomic_subl(int* v, int sub) { 
    return pz_atomic_addl(v, -sub); }
