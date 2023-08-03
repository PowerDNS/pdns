# Find bison
# Outputs: bison

bison = find_program('bison', required: true)
summary('bison', bison.found(), bool_yn: true, section: 'Programs')
# summary('Bison', bison.full_path(), section: 'System')       # TODO Meson 0.55
# summary('Bison Version', bison.version(), section: 'System') # TODO Meson 0.62

bison_generator = generator(
  bison,
  output: '@BASENAME@.cc',
  arguments: ['--verbose', '--debug', '--header=@BUILD_DIR@' / '@BASENAME@.h', '--output=@OUTPUT@', '@INPUT@'],
)
