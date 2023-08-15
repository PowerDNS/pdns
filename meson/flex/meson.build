flex = find_program('flex', required: true)

summary('Flex', flex.found(), bool_yn: true, section: 'Programs')
summary('Flex Path', flex.full_path(), section: 'Programs')
summary('Flex Version', flex.version(), section: 'Programs')

flex_generator = generator(
  flex,
  output: '@BASENAME@.c',
  arguments: ['--case-insensitive', '--outfile=@OUTPUT@', '@INPUT@'],
)
