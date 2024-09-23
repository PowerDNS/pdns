#include <pthread.h>
#if HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif

int main()
{
  pthread_set_name_np(pthread_self(), "foo");
  return 0;
}
