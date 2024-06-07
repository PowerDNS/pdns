dep_cxx_fs = dependency('', required: false)

if get_option('module-geoip') != 'disabled'
  need_cxx_fs = false

  prog = fs.read('cxx-fs.cc')
  if not cxx.links(prog, name: '-lstdc++fs and -lc++fs are not needed')
    lib_cxx_fs = cxx.find_library('stdc++fs', disabler: true, required: false)
    if lib_cxx_fs.found()
      if cxx.links(prog, name: '-lstdc++fs is needed', dependencies: lib_cxx_fs)
        need_cxx_fs = true
        dep_cxx_fs = declare_dependency(dependencies: lib_cxx_fs)
        summary('Filesystem library', lib_cxx_fs, section: 'System')
      endif
    endif

    if need_cxx_fs == false
      lib_cxx_fs = cxx.find_library('c++fs', disabler: true, required: false)
      if lib_cxx_fs.found()
        if cxx.links(prog, name: '-lc++fs is needed', dependencies: lib_cxx_fs)
          need_cxx_fs = true
          dep_cxx_fs = declare_dependency(dependencies: lib_cxx_fs)
          summary('Filesystem library', lib_cxx_fs, section: 'System')
        else
          error('C++ Filesystem library was found but linking against it failed')
        endif
      else
        error('C++ Filesystem library is needed but could not be found')
      endif
    endif
  else
    dep_cxx_fs = declare_dependency()
  endif

  summary('Need -lstdc++fs/-lc++fs', need_cxx_fs, bool_yn: true, section: 'System')
endif
