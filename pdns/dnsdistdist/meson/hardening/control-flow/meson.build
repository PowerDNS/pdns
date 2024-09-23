opt_cf = get_option('hardening-experimental-cf')

support_cf_prot = opt_cf != 'disabled' and cxx.has_argument('-fcf-protection=' + opt_cf)
if support_cf_prot
  add_project_arguments('-fcf-protection=' + opt_cf, language: ['c', 'cpp'])
elif opt_cf != 'disabled'
  error('Control Flow Protection was explicitly requested but is not supported by the compiler')
endif

summary('Control Flow Protection', support_cf_prot, bool_yn: true, section: 'Hardening')
