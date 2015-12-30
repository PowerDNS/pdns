#include <string>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "dns_random.hh"

/* pthread locking */

static pthread_mutex_t *locks;

void openssl_pthreads_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&(locks[type]));
  else
    pthread_mutex_unlock(&(locks[type]));
}

unsigned long openssl_pthreads_id_callback()
{
  return (unsigned long)pthread_self();
}

void openssl_thread_setup()
{
  locks = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

  for (int i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_init(&(locks[i++]), NULL);

  CRYPTO_set_id_callback((unsigned long (*)())openssl_pthreads_id_callback);
  CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))openssl_pthreads_locking_callback);
}

void openssl_thread_cleanup()
{
  CRYPTO_set_locking_callback(NULL);

  for (int i=0; i<CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(locks[i]));

  OPENSSL_free(locks);
}


/* seeding PRNG */

void openssl_seed()
{
  std::string entropy;
  entropy.reserve(1024);

  unsigned int r;
  for(int i=0; i<1024; i+=4) {
    r=dns_random(0xffffffff);
    entropy.append((const char*)&r, 4);
  }

  RAND_seed((const unsigned char*)entropy.c_str(), 1024);
}
