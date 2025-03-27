opt_libsnmp = get_option('snmp')
dep_libsnmp = dependency('', required: false)

if opt_libsnmp.allowed()
    snmp_config = find_program('net-snmp-config', required: opt_libsnmp)
    if snmp_config.found()
      snmp_ldflags_res = run_command(snmp_config, '--netsnmp-agent-libs', check: false)
      if snmp_ldflags_res.returncode() == 0
        snmp_ldflags = snmp_ldflags_res.stdout().strip().split()

        dep_libsnmp = declare_dependency(
          link_args: snmp_ldflags,
        )

        if dep_libsnmp.found()
          funcs = [
           'snmp_select_info2',
          ]

          foreach func: funcs
            define = 'HAVE_' + func.to_upper()
            have_func = cxx.has_function(func, dependencies: dep_libsnmp, prefix: '''#include <net-snmp/net-snmp-config.h>
                #include <net-snmp/definitions.h>
                #include <net-snmp/types.h>
                #include <net-snmp/utilities.h>
                #include <net-snmp/config_api.h>
                #include <net-snmp/session_api.h>''')
            conf.set(define, have_func, description: 'Have libsnmp ' + func)
          endforeach
       endif
     endif
   endif
endif

if opt_libsnmp.enabled() and not dep_libsnmp.found()
  error('SNMP support enabled but not available')
endif

conf.set('HAVE_NET_SNMP', dep_libsnmp.found(), description: 'libsnmp')
summary('SNMP', dep_libsnmp.found(), bool_yn: true, section: 'Configuration')
