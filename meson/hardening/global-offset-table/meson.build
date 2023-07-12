# Read-only Global Offset Table
# Inputs: hardening_features deps

ld_help = run_command(cxx, '-Wl,-help', '2>&1', check: true).stdout().strip()
variants = ['relro', 'now']
found_variant = false
foreach variant: variants
  if ld_help.contains('-z ' + variant)
    found_variant = true
    dep_relro = declare_dependency(link_args: ['-Wl,-z', '-Wl,' + variant])
    deps += dep_relro
  endif
endforeach

hardening_features += [[found_variant, 'Read-only Global Offset Table']]
summary('Read-only GOT', found_variant, bool_yn: true, section: 'Hardening')
