dep_libresolv = dependency('resolv', required: false)

need = false
if not dep_libresolv.found()
  # Dependency resolving does not work for macOS
  if build_machine.system() == 'darwin'
    add_project_link_arguments('-lresolv', language: 'cpp')
    need = true
  else
    lib_resolv = cxx.find_library('resolv', disabler: true, required: false)
    if lib_resolv.found()
      if cxx.links(prog, name: '-lresolv is needed', dependencies: lib_resolv)
        need = true
        dep_libresolv = declare_dependency(dependencies: lib_resolv)
      endif
    endif
  endif
else
  need = true
endif

summary('Need -lresolv', need, bool_yn: true, section: 'System')
