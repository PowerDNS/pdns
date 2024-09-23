prog_single_pointer = fs.read('sanitizer_finish_switch_fiber_1ptr.cc')
prog_three_pointers = fs.read('sanitizer_finish_switch_fiber_3ptrs.cc')

single_pointer = false
three_pointers = false

if cxx.check_header('sanitizer/common_interface_defs.h', required: false)
  if cxx.has_header_symbol('sanitizer/common_interface_defs.h', '__sanitizer_start_switch_fiber', required: false)
    if cxx.compiles(prog_single_pointer, name: '__sanitizer_finish_switch_fiber with a single pointer')
      single_pointer = true
    endif

    if cxx.compiles(prog_three_pointers, name: '__sanitizer_finish_switch_fiber with three pointers')
      three_pointers = true
    endif
  else
    warning('Address Sanitizer fiber switching is not available')
  endif

else
  warning('Address Sanitizer requested but `sanitizer/common_interface_defs.h` ' +
          'is invalid or cannot be found. Address Sanitizer fiber switching is ' +
          'not available')
endif

if not single_pointer and not three_pointers
  warning('Address Sanitizer fiber switching is not available due to an unknown API version')
endif

conf.set(
  'HAVE_FIBER_SANITIZER',
  single_pointer or three_pointers,
  description: 'Address Sanitizer fiber annotation interface is available',
)
conf.set(
  'HAVE_SANITIZER_FINISH_SWITCH_FIBER_SINGLE_PTR',
  single_pointer,
  description: 'Address Sanitizer: __sanitizer_finish_switch_fiber takes only a pointer',
)
conf.set(
  'HAVE_SANITIZER_FINISH_SWITCH_FIBER_THREE_PTRS',
  three_pointers,
  description: 'Address Sanitizer: __sanitizer_finish_switch_fiber takes three pointers',
)
