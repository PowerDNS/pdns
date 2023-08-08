# Fortify Source
# Inputs: hardening_features

fortify_source_opt = get_option('fortify-source')

if fortify_source_opt != 'disabled'
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
        add_global_arguments('-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=' + variant_str, language: ['cpp'])
        break
      else
        fortify_source_level = fortify_source_level - 1
      endif
    endif
  endforeach

  if fortify_source_level == 0
    fortify_source_level = 'no'
  endif

  hardening_features += [[fortify_source_level != 0, 'Source Fortification']]
  summary('Source Fortification Level', fortify_source_level, section: 'Hardening')
endif
