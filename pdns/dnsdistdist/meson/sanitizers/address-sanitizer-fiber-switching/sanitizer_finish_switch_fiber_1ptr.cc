#include <sanitizer/common_interface_defs.h>

int main()
{
  __sanitizer_finish_switch_fiber(nullptr);
  return 0;
}
