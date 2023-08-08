# Hardening
opt_hardening = get_option('hardening')

if opt_hardening.enabled() or opt_hardening.auto()
  hardening_features = []

  # TODO Use meson's -Db_pie and -Db_staticpic options?
  # subdir('pie')                 # PIE
  subdir('stack-prot')          # Stack Protector
  subdir('stack-smashing-prot') # Stack-Smashing Protection
  subdir('fortify-source')      # Fortify Source
  subdir('global-offset-table') # Read-only Global Offset Table

  foreach feature: hardening_features
    available = feature[0]
    name = feature[1]

    if not available
      if opt_hardening.auto()
        warning(name + ' is not supported')
      else
        error('Failing because ' + name + ' is not supported but hardening was explicitly requested')
      endif
    endif
  endforeach
endif
