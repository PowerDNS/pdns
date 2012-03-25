#include "crypto_sign.h"
#include "crypto_hash_sha512.h"
#include "ge.h"

int crypto_sign_publickey(
    unsigned char *pk,  // write 32 bytes into this
    unsigned char *sk,  // write 64 bytes into this (seed+pubkey)
    unsigned char *seed // 32 bytes input
    )
{
  unsigned char h[64];
  ge_p3 A;
  int i;

  crypto_hash_sha512(h,seed,32);
  h[0] &= 248;
  h[31] &= 63;
  h[31] |= 64;

  ge_scalarmult_base(&A,h);
  ge_p3_tobytes(pk,&A);

  for (i = 0;i < 32;++i) sk[i] = seed[i];
  for (i = 0;i < 32;++i) sk[32 + i] = pk[i];
  return 0;
}
