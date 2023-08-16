lib_ipcrypt = static_library(
  'ipcrypt',
  'ipcrypt.c',
  extra_files: [
    'ipcrypt.h',
    'LICENSE',
  ],
)

dep_ipcrypt = declare_dependency(
  link_with: lib_ipcrypt,
  include_directories: include_directories('.'),
)
