auto_var_init = get_option('auto-var-init')

if auto_var_init != 'disabled'
  arg = '-ftrivial-auto-var-init=' + auto_var_init
  if cxx.has_argument(arg)
    add_project_arguments(arg, language: ['c', 'cpp'])
  else
    warning('Compiler does not support ' + arg + ', which is needed for automatic variable initialization')
    auto_var_init = 'unsupported by compiler'
  endif
endif

summary('Auto Var Init', auto_var_init, section: 'Configuration')
