opt_libdecaf = get_option('signers-libdecaf')
dep_libdecaf = dependency('', required: false)

found_header = false
header_path = false

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
    include_dirs = [
      '/usr' / 'include',
      '/usr' / 'include' / 'decaf',
      '/usr' / 'local' / 'include',
      '/usr' / 'local' / 'include' / 'decaf',
    ]

    do_break = false
    foreach dirname: include_dirs
      dir = include_directories(dirname, is_system: true)

      header_path = dirname / 'decaf.hxx'
      message('Libdecaf: Checking for ' + header_path)

      found_header = cxx.has_header(
        'decaf.hxx',
        dependencies: dep_libdecaf,
        required: false,
        include_directories: dir,
      )

      if found_header
        dep_libdecaf = declare_dependency(
          include_directories: dir,
          dependencies: dep_libdecaf,
        )

        break
      endif
    endforeach
  endif
endif

conf.set('HAVE_LIBDECAF', dep_libdecaf.found() and found_header, description: 'libdecaf-based signers')
summary('libdecaf', dep_libdecaf.found(), bool_yn: true, section: 'Crypto')

if dep_libdecaf.found()
  summary('libdecaf headers', header_path, bool_yn: true, section: 'Crypto')
endif
