#ifndef PDNS_RDTSC_HH
#define PDNS_RDTSC_HH



#define RDTSC(qp) \
do { \
  unsigned long lowPart, highPart;        				\
  __asm__ __volatile__("cpuid"); \
  __asm__ __volatile__("rdtsc" : "=a" (lowPart), "=d" (highPart)); \
    qp = (((unsigned long long) highPart) << 32) | lowPart; \
} while (0)

#endif
