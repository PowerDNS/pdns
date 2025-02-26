fortify_source_opt = get_option('hardening-fortify-source')
fortify_source = fortify_source_opt != 'disabled'
fortify_source_level = 0

if fortify_source and get_option('buildtype') == 'debug'
  error('Source fortification was requested but it requires compiling with optimization. ' +
        'A debug buildtype was requested, try setting buildtype=debugoptimized instead')
endif

if fortify_source
  fortify_source_level = 2
  if fortify_source_opt == 'auto'
    fortify_source_level = 3
  else
    fortify_source_level = fortify_source_opt.to_int()
  endif

  variants = [3, 2, 1]
  foreach variant: variants
    variant_str = variant.to_string()
    if fortify_source_level == variant
      if cxx.has_argument('-D_FORTIFY_SOURCE=' + variant_str)
        add_project_arguments('-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=' + variant_str, language: ['c', 'cpp'])
        break
      else
        fortify_source_level = fortify_source_level - 1
      endif
    endif
  endforeach
endif

fortify_source = fortify_source and fortify_source_level != 0
summary('Source Fortification', fortify_source, bool_yn: true, section: 'Hardening')

if fortify_source
  summary('Source Fortification Level', fortify_source_level, section: 'Hardening')
endif
