# Libdecaf-based signers
# Inputs: deps conf

opt_libdecaf = get_option('libdecaf')
dep_libdecaf = dependency('', required: false)

if not opt_libdecaf.disabled()
  dep_libdecaf = dependency('libdecaf', required: false)
  if not dep_libdecaf.found()
    dep_libdecaf = cxx.find_library('decaf', dirs: ['/usr', '/usr/local'], required: opt_libdecaf)
  endif

  found_header = false
  header_path = ''
  if dep_libdecaf.found()
    include_dirs = ['/usr/include', '/usr/local/include']
    headers = ['decaf.hxx', 'decaf/decaf.hxx']

    do_break = false
    foreach dirname: include_dirs
      dir = include_directories(dirname, is_system: true)
      foreach header: headers
        header_path = dirname / header
        message('Libdecaf: Checking for ' + header_path)
        found_header = cxx.has_header(header, dependencies: dep_libdecaf, required: false, include_directories: dir)
        if found_header
          add_global_arguments('-I' + dirname, language: 'cpp')
          do_break = true
          break
        endif
      endforeach

      if do_break
        break
      endif
    endforeach
  endif

  show_colors = dep_libdecaf.found() or not opt_libdecaf.auto()
  conf.set10('HAVE_LIBDECAF', dep_libdecaf.found() and found_header, description: 'Whether we build libdecaf-based signers')
  summary('libdecaf', dep_libdecaf.found(), bool_yn: show_colors, section: 'Configuration')
  summary('libdecaf headers', found_header ? header_path : found_header, bool_yn: show_colors, section: 'Configuration')
endif
