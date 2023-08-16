auto_var_init = get_option('auto-var-init')

if auto_var_init != 'disabled'
  arg = '-ftrivial-auto-var-init=' + auto_var_init
  if not cxx.has_argument(arg)
    error('Compiler does not support ' + arg + ', which is needed for automatic variable initialization')
    subdir_done()
  endif

  add_global_arguments(arg, language: ['c', 'cpp'])
endif

summary('Auto Var Init', auto_var_init, section: 'Configuration')
