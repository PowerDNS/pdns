#include "config.h"

//#ifdef HAVE_SYS_RANDOM_H
//#include <sys/random.h>
//#endif

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include <errno.h>
#include <unistd.h>

#define seed_from_prngd(a, b) -1

uint32_t arc4random(void);
void arc4random_buf(void *buf, size_t nbytes);
uint32_t arc4random_uniform(uint32_t upper_bound);

#define DEF_WEAK(x)
