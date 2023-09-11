opt_sanitize = get_option('b_sanitize')

if opt_sanitize == 'address' or opt_sanitize == 'address,undefined'
  subdir('address-sanitizer-fiber-switching')
endif

if opt_sanitize != 'none'
  add_project_arguments('-fno-omit-frame-pointer', language: ['c', 'cpp'])
endif

summary('Sanitizers', opt_sanitize, bool_yn: true, section: 'Configuration')
