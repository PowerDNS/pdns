#include <cstdint>

int main()
{
  uint64_t val = 0;
  __atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);
  return 0;
}
