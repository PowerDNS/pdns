# Don't limit the number of errors when using clang. This is useful to not cut out the
# error output when using an LSP server like clangd.
if meson.get_compiler('cpp').get_id() == 'clang'
  add_project_arguments('-ferror-limit=0', language: ['c', 'cpp'])
endif

add_project_arguments(
  '-Wshadow',
  '-Wmissing-declarations',
  '-Wredundant-decls',
  '-Wno-ignored-attributes',
  '-fvisibility=hidden',
  language: ['c', 'cpp'],
)

cxx = meson.get_compiler('cpp')
system = target_machine.system()

if cxx.get_id() == 'gcc' and cxx.version().version_compare('>=8.0,<9.0')
  add_global_link_arguments('-lstdc++fs', language: ['c', 'cpp'])
endif

