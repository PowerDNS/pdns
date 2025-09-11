lib_ipcrypt2 = static_library(
  'ipcrypt2',
  'ipcrypt2.c',
  extra_files: [
    'include/ipcrypt2.h',
    'LICENSE',
    'README.md',
  ],
)

dep_ipcrypt2 = declare_dependency(
  link_with: lib_ipcrypt2,
  include_directories: include_directories('./include'),
)
