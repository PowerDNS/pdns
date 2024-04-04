opt_libdecaf = get_option('signers-libdecaf')
dep_libdecaf = dependency('', required: false)

if not opt_libdecaf.disabled()
  dep_libdecaf = dependency('libdecaf', required: false)

  if not dep_libdecaf.found()
    dep_libdecaf = cxx.find_library(
      'decaf',
      dirs: [
        '/usr',
        '/usr' / 'lib',
        '/usr' / 'local',
        '/usr' / 'local' / 'lib',
      ],
      required: opt_libdecaf
    )
  endif

  if dep_libdecaf.found()
    message('Libdecaf: Checking for header file')

    include_dirs = include_directories(
      '/usr' / 'include',
      '/usr' / 'include' / 'decaf',
      '/usr' / 'local' / 'include',
      '/usr' / 'local' / 'include' / 'decaf',
      is_system: true,
    )

    cxx.has_header(
      'decaf.hxx',
      required: true,
      include_directories: include_dirs,
    )

    dep_libdecaf = declare_dependency(
      include_directories: dir,
      dependencies: dep_libdecaf,
    )
  endif
endif

conf.set('HAVE_LIBDECAF', dep_libdecaf.found(), description: 'libdecaf-based signers')
summary('libdecaf', dep_libdecaf.found(), bool_yn: true, section: 'Crypto')
