#include <string>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "dns_random.hh"

/* pthread locking */
void openssl_thread_setup();
void openssl_thread_cleanup();

/* seeding PRNG */
void openssl_seed();
