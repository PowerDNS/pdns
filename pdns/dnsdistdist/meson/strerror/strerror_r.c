#include <string.h>

int main () {
  char error_string[256];
  char *ptr = strerror_r(-2, error_string, 256);
  char c = *strerror_r(-2, error_string, 256);
  return c != 0 && ptr != (void*) 0L;
}
