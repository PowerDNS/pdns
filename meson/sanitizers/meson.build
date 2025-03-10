opt_sanitize = get_option('b_sanitize')
leak_detection = false

if opt_sanitize == 'address' or opt_sanitize == 'address,undefined'
  subdir('address-sanitizer-fiber-switching')
  leak_detection = true
endif

if opt_sanitize == 'leak'
  leak_detection = true
endif

if leak_detection
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
