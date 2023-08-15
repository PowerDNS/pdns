ragel = find_program('ragel', required: false)

summary('Ragel', ragel.found(), bool_yn: ragel.found(), section: 'Programs')
summary('Ragel Path', ragel.full_path(), section: 'Programs')
summary('Ragel Version', ragel.version(), section: 'Programs')

ragel_generator = generator(
  ragel,
  output: '@BASENAME@.cc',
  arguments: ['@INPUT@', '-o', '@OUTPUT@'],
)
