# Find Ragel and create generator
# Outputs: ragel

ragel = find_program('ragel', required: false)
summary('Ragel', ragel.found(), bool_yn: ragel.found(), section: 'Programs')
# summary('Ragel', ragel.full_path(), section: 'System')       # TODO Meson 0.55
# summary('Ragel Version', ragel.version(), section: 'System') # TODO Meson 0.62

ragel_generator = generator(
  ragel,
  output: '@BASENAME@.cc',
  arguments: ['@INPUT@', '-o', '@OUTPUT@'],
)
