opt_libsnmp = get_option('snmp')

if get_option('snmp')
    snmp_config = find_program('net-snmp-config', required: true)
    snmp_ldflags_res = run_command(snmp_config, '--libs', check: true)
    snmp_ldflags = snmp_ldflags_res.stdout().strip().split()
    snmp_ldflags_res = run_command(snmp_config, '--agent-libs', check: true)
    snmp_ldflags += snmp_ldflags_res.stdout().strip().split()

    dep_libsnmp = declare_dependency(
      link_args: snmp_ldflags,
    )
endif

if dep_libsnmp.found()
  funcs = [
    'snmp_select_info2',
  ]

  foreach func: funcs
    define = 'HAVE_' + func.to_upper()
    have_func = cxx.has_function(func, dependencies: dep_libsnmp)
    conf.set(define, have_func, description: 'Have libsnmp ' + func)
  endforeach
endif

conf.set('HAVE_LIBSSNMP', dep_libsnmp.found(), description: 'libsnmp')
summary('SNMP', dep_libsnmp.found(), bool_yn: true, section: 'Configuration')
