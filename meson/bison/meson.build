bison = find_program('bison', required: true)

summary('Bison', bison.found(), bool_yn: true, section: 'Programs')
summary('Bison Path', bison.full_path(), section: 'Programs')
summary('Bison Version', bison.version(), section: 'Programs')

bison_generator = generator(
  bison,
  output: '@BASENAME@.cc',
  arguments: ['-d', '--verbose', '--debug', '--output=@OUTPUT@', '@INPUT@'],
)
