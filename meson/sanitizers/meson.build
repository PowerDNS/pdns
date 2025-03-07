opt_sanitize = get_option('b_sanitize')

if opt_sanitize == 'address' or opt_sanitize == 'address,undefined'
  subdir('address-sanitizer-fiber-switching')
  conf.set(
    'HAVE_LEAK_SANITIZER_INTERFACE',
    cxx.has_header('sanitizer/lsan_interface.h'),
    description: 'Have leak sanitizer inteface',
  )
endif

if opt_sanitize != 'none'
  add_project_arguments('-fno-omit-frame-pointer', language: ['c', 'cpp'])
endif

summary('Sanitizers', opt_sanitize, bool_yn: true, section: 'Configuration')
