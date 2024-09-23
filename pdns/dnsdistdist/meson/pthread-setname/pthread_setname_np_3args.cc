#include <pthread.h>
#if HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif

int main()
{
  return pthread_setname_np(pthread_self(), "foo", NULL);
}
