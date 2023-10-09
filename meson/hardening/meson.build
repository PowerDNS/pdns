opt_hardening = get_option('hardening')
if opt_hardening.enabled() or opt_hardening.auto()
  hardening_features = []

  # PIE
  opt_pie = get_option('b_pie')
  if not opt_pie and opt_hardening.enabled()
    error('Hardening was requested but building position independent executables is disabled')
  endif
  hardening_features += [[opt_pie, 'Building position independent executables (PIEs)']]
  conf.set('PIE', opt_pie, description: 'Build a Position Independent Executable (PIE)')
  summary('PIE', opt_pie, bool_yn: true, section: 'Hardening')

  subdir('stack-prot')          # Stack Protector
  subdir('stack-smashing-prot') # Stack-Smashing Protection
  subdir('fortify-source')      # Fortify Source
  subdir('relro')               # RELRO

  foreach feature: hardening_features
    available = feature[0]
    name = feature[1]

    if not available
      if opt_hardening.auto()
        warning(name + ' is disabled or not supported')
      else
        error('Failing because ' + name + ' is not supported but hardening was requested')
      endif
    endif
  endforeach
endif

opt_full_hardening = get_option('hardening-full')
if opt_full_hardening.enabled() or opt_full_hardening.auto()
  full_hardening_features = []
  subdir('relro-full')          # Full RELRO

  foreach feature: full_hardening_features
    available = feature[0]
    name = feature[1]

    if not available
      if opt_full_hardening.auto()
        warning(name + ' is disabled or not supported')
      else
        error('Failing because ' + name + ' is not supported but full hardening was requested')
      endif
    endif
  endforeach
endif
