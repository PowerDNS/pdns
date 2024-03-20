#include <p11-kit/p11-kit.h>

int main()
{
  __attribute__((unused)) void* foo = p11_kit_module_for_name(nullptr, nullptr);
  return 0;
}
