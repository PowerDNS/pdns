# Link-time Optimization

opt_lto = get_option('lto')

if opt_lto == 'thin'
  compiler_opt = '-flto=thin'
  if cxx.has_argument(compiler_opt)
    add_project_arguments(compiler_opt, language: ['c', 'cpp'])
    add_project_link_arguments(compiler_opt, language: ['c', 'cpp'])
  else
    opt_lto = 'auto'
  endif
endif

if opt_lto == 'auto'
  compiler_opt = '-flto=auto'
  if cxx.has_argument(compiler_opt)
    add_project_arguments(compiler_opt, language: ['c', 'cpp'])
    add_project_link_arguments(compiler_opt, language: ['c', 'cpp'])
  else
    opt_lto = 'yes'
  endif
endif

if opt_lto == 'yes'
  compiler_opt = '-flto'
  if cxx.has_argument(compiler_opt)
    add_project_arguments(compiler_opt, language: ['c', 'cpp'])
    add_project_link_arguments(compiler_opt, language: ['c', 'cpp'])
  else
    error('LTO was requested but is not supported')
  endif
endif

summary('LTO', opt_lto, section: 'Configuration')
