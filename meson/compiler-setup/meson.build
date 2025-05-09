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
  language: ['c', 'cpp'],
)

cxx = meson.get_compiler('cpp')
system = target_machine.system()

link_no_warn_duplicate_libraries = cxx.get_supported_link_arguments([
  '-Wl,-no_warn_duplicate_libraries',
])

add_project_link_arguments(link_no_warn_duplicate_libraries, language: ['c', 'cpp'])
