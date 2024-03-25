variants = [
  [
    '2-arg pthread_setname_np',
    'HAVE_PTHREAD_SETNAME_NP_2',
    'pthread_setname_np takes 2 arguments (Linux/glibc, QNX, IBM)',
    fs.read('pthread_setname_np_2args.cc'),
  ],
  [
    '2-arg pthread_set_name_np',
    'HAVE_PTHREAD_SET_NAME_NP_2',
    'pthread_set_name_np takes 2 arguments and does not return void (FreeBSD, OpenBSD)',
    fs.read('pthread_set_name_np_2args.cc'),
  ],
  [
    '2-arg void pthread_set_name_np',
    'HAVE_PTHREAD_SET_NAME_NP_2_VOID',
    'pthread_set_name_np takes 2 arguments and returns void (FreeBSD, OpenBSD)',
    fs.read('pthread_set_name_np_void_2args.cc'),
  ],
  [
    '1-arg pthread_setname_np',
    'HAVE_PTHREAD_SETNAME_NP_1',
    'pthread_setname_np takes 1 argument (Darwin, MacOS)',
    fs.read('pthread_setname_np_1arg.cc'),
  ],
  [
    '3-arg pthread_setname_np',
    'HAVE_PTHREAD_SETNAME_NP_3',
    'pthread_setname_np takes 3 arguments (NetBSD)',
    fs.read('pthread_setname_np_3args.cc'),
  ],
]

found = false
foreach variant: variants
  variant_name = variant[0]
  variant_define = variant[1]
  variant_description = variant[2]
  variant_program = variant[3]

  if cxx.links(
    variant_program,
    name: variant_name,
    dependencies: dep_threads,
    args: have_pthread_np_h ? ['-DHAVE_PTHREAD_NP_H'] : []
  )
    found = true
    conf.set(variant_define, true, description: variant_description)
    summary('pthread_setname Variant', variant_define, section: 'POSIX Threads')
    summary('Description', variant_description, section: 'POSIX Threads')
    break
  endif
endforeach

if not found
  error('Could not find a suitable pthread_setname function')
endif
