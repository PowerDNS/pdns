# Hardening
opt_hardening = get_option('hardening')

if opt_hardening.enabled() or opt_hardening.auto()
  hardening_features = []

  # PIE
  opt_pie = get_option('b_pie')
  if not opt_pie
    error('Hardening was requested but building position independent executables is disabled')
  endif
  hardening_features += [[opt_pie, 'Building position independent executables (PIEs)']]
  conf.set10('PIE', opt_pie, description: 'Whether we enable building a Position Independent Executable (PIE)')
  summary('PIE', opt_pie, bool_yn: true, section: 'Hardening')

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
