opt_scp = get_option('hardening-experimental-scp')

support_scp = not opt_scp.disabled() and cxx.has_argument('-fstack-clash-protection')
if support_scp
  add_project_arguments('-fstack-clash-protection', language: ['c', 'cpp'])
elif opt_scp.enabled()
  error('Stack Clash Protection was explicitly requested but is not supported by the compiler')
endif

summary('Stack Clash Protection', support_scp, bool_yn: true, section: 'Hardening')
