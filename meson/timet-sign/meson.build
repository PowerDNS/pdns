# Check the sign of time_t

prog = '''
#include <sys/types.h>

int main() {
  int foo[1 - 2 * !(((time_t) -1) < 0)];
  (void)foo[0];
  return 0;
}
'''

timet_signed = cxx.compiles(prog, name: 'time_t is signed')

if not timet_signed
  error('time_t is unsigned, PowerDNS code relies on it being signed')
endif

summary('Signed time_t', timet_signed, bool_yn: true, section: 'System')
