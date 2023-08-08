# Address Sanitizer
# Inputs: conf

opt_address_sanitizer = get_option('sanitizer-address')

if not opt_address_sanitizer
  subdir_done()
endif

if not cxx.has_argument('-fsanitize=address')
  error('Address Sanitizer requested but compiler does not support `-fsanitize=address`')
endif

if not cxx.check_header('sanitizer/common_interface_defs.h')
  error('Address Sanitizer requested but `sanitizer/common_interface_defs.h` is invalid or cannot be found')
endif

if not cxx.has_header_symbol('sanitizer/common_interface_defs.h', '__sanitizer_start_switch_fiber', required: false)
  warning('Address Sanitizer fiber switching is not available')
endif

single_pointer = false
prog_single_pointer = '''
#include <sanitizer/common_interface_defs.h>

int main() {
  __sanitizer_finish_switch_fiber(nullptr);
  return 0;
}
'''

three_pointers = false
prog_three_pointers = '''
#include <sanitizer/common_interface_defs.h>

int main() {
  __sanitizer_finish_switch_fiber(nullptr, nullptr, nullptr);
  return 0;
}
'''

if cxx.compiles(prog_single_pointer, name: '__sanitizer_finish_switch_fiber with a single pointer')
  single_pointer = true
endif

if cxx.compiles(prog_three_pointers, name: '__sanitizer_finish_switch_fiber with three pointers')
  three_pointers = true
endif

if not single_pointer and not three_pointers
  warning('Address Sanitizer fiber switching is not available due to an unknown API version')
endif

conf.set10('HAVE_FIBER_SANITIZER', single_pointer or three_pointers, description: 'Address Sanitizer fiber annotation interface is available')
conf.set10('HAVE_SANITIZER_FINISH_SWITCH_FIBER_SINGLE_PTR', single_pointer, description: 'Address Sanitizer: __sanitizer_finish_switch_fiber takes only a pointer')
conf.set10('HAVE_SANITIZER_FINISH_SWITCH_FIBER_THREE_PTRS', three_pointers, description: 'Address Sanitizer: __sanitizer_finish_switch_fiber takes three pointers')

add_global_arguments('-fsanitize=address', language: ['cpp'])

summary('address', opt_address_sanitizer, bool_yn: true, section: 'Sanitizers')
