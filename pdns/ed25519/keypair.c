#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "ge.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void randombytes(unsigned char* sk, unsigned int amount)
{
  int fd = open("/dev/urandom", O_RDONLY);
  if(fd < 0) {
    perror("opening random");
    exit(1);
  }
  if(read(fd, sk, amount) != amount) {
    fprintf(stderr,"Unable to get %d bytes of random", amount);
    exit(1);
  }
  close(fd);
}

int crypto_sign_keypair(unsigned char *pk,unsigned char *sk)
{
  unsigned char h[64];
  ge_p3 A;
  int i;

  randombytes(sk,32);
  crypto_hash_sha512(h,sk,32);
  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;

  ge_scalarmult_base(&A,h);
  ge_p3_tobytes(pk,&A);

  for (i = 0;i < 32;++i) sk[32 + i] = pk[i];
  return 0;
}
