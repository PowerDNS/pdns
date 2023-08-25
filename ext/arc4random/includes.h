#pragma once

#include "config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#include <errno.h>
#include <unistd.h>

#define seed_from_prngd(a, b) -1

#ifndef HAVE_ARC4RANDOM
uint32_t arc4random(void);
#endif
#ifndef HAVE_ARC4RANDOM_BUF
void arc4random_buf(void *buf, size_t nbytes);
#endif
#ifndef HAVE_ARC4RANDOM_UNIFORM
uint32_t arc4random_uniform(uint32_t upper_bound);
#endif
#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *, size_t len);
#endif

int _ssh_compat_getentropy(void *, size_t);

#define DEF_WEAK(x)
