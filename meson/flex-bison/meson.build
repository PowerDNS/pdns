# Find flex and bison
# Outputs: flex bison

flex = find_program('flex', required: true)
summary('flex', flex.found(), bool_yn: true, section: 'Programs')
# summary('Flex', flex.full_path(), section: 'System')       # TODO Meson 0.55
# summary('Flex Version', flex.version(), section: 'System') # TODO Meson 0.62

bison = find_program('bison', required: true)
summary('bison', bison.found(), bool_yn: true, section: 'Programs')
# summary('Bison', bison.full_path(), section: 'System')       # TODO Meson 0.55
# summary('Bison Version', bison.version(), section: 'System') # TODO Meson 0.62
