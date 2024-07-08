dep_libresolv = dependency('resolv', required: false)

need = false
if build_machine.system() == 'darwin'
  add_project_link_arguments('-lresolv', language: 'cpp')
  need = true
endif

summary('Need -lresolv', need, bool_yn: true, section: 'System')
