#include <sys/types.h>

int main()
{
  int foo[1 - 2 * !(((time_t)-1) < 0)];
  (void)foo[0];
  return 0;
}
