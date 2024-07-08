opt_libsnmp = get_option('snmp')
dep_libsnmp = dependency('libsnmp', required: opt_libsnmp)

conf.set('HAVE_LIBSSNMP', dep_libsnmp.found(), description: 'libsnmp')
summary('SNMP', dep_libsnmp.found(), bool_yn: true, section: 'Configuration')
