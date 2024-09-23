lib_ipcrypt = static_library(
  'ipcrypt',
  'ipcrypt.c',
  extra_files: [
    'ipcrypt.h',
  ],
)

dep_ipcrypt = declare_dependency(
  link_with: lib_ipcrypt,
  include_directories: include_directories('.'),
)
