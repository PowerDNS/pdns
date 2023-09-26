found_variant = false

ld_help_result = run_command(cxx, '-Wl,-help', check: false)
if ld_help_result.returncode() != 0
  warning('Linker does not support help text output. ' +
          'Read-only global offset table will be disabled')
else
  ld_help = ld_help_result.stdout().strip()
  variants = ['relro', 'now']
  foreach variant: variants
    if ld_help.contains('-z ' + variant)
      found_variant = true
      add_project_link_arguments('-Wl,-z', '-Wl,' + variant, language: ['c', 'cpp'])
    endif
  endforeach
endif

hardening_features += [[found_variant, 'Read-only Global Offset Table']]
summary('Read-only GOT', found_variant, bool_yn: true, section: 'Hardening')
