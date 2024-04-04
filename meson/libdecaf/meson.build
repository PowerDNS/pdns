opt_libdecaf = get_option('signers-libdecaf')
dep_libdecaf = dependency('', required: false)

if not opt_libdecaf.disabled()
  dep_libdecaf = dependency('libdecaf', required: false)

  if not dep_libdecaf.found()
    all_lib_dirs = [
      '/usr',
      '/usr' / 'lib',
      '/usr' / 'local',
      '/usr' / 'local' / 'lib',
    ]

    all_include_dirs = [
      '/usr' / 'include',
      '/usr' / 'include' / 'decaf',
      '/usr' / 'local' / 'include',
      '/usr' / 'local' / 'include' / 'decaf',
    ]

    fs = import('fs')

    lib_dirs = []
    foreach lib_dir: all_lib_dirs
      if fs.is_dir(lib_dir)
        lib_dirs += lib_dir
      endif
    endforeach

    include_dirs = []
    foreach include_dir: all_include_dirs
      if fs.is_dir(include_dir)
        include_dirs += include_dir
      endif
    endforeach
    include_dirs = include_directories(include_dirs, is_system: true)

    dep_libdecaf = cxx.find_library(
      'decaf',
      dirs: lib_dirs,
      required: opt_libdecaf,
      has_headers: [
        'decaf.hxx',
        'decaf' / 'spongerng.hxx',
        'decaf' / 'eddsa.hxx',
      ],
      header_include_directories: include_dirs,
    )

    dep_libdecaf = declare_dependency(
      dependencies: dep_libdecaf,
      include_directories: include_dirs,
    )
  endif
endif

conf.set('HAVE_LIBDECAF', dep_libdecaf.found(), description: 'libdecaf-based signers')
summary('libdecaf', dep_libdecaf.found(), bool_yn: true, section: 'Crypto')
