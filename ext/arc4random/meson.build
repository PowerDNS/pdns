lib_arc4random = static_library(
  'arc4random',
  'arc4random.c',
  'arc4random_uniform.c',
  'bsd-getentropy.c',
  'explicit_bzero.c',
  extra_files: [
    'arc4random.h',
    'arc4random.hh',
    'chacha_private.h',
    'includes.h',
    'log.h',
  ],
  dependencies: [dep_pdns],
)

dep_arc4random = declare_dependency(
  link_with: lib_arc4random,
  include_directories: include_directories('.'),
)
