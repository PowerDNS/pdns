have_full_relro = true
full_variants = [
  '-Wl,-z,defs',
  '-Wl,-z,ibt,-z,shstk',
]

foreach variant: full_variants
  if cxx.has_link_argument(variant)
    full_hardening_features += [[true, 'Full RELRO (' + variant + ')']]
    add_project_link_arguments(variant, language: ['c', 'cpp'])
  else
    have_full_relro = false
  endif
endforeach

summary('Full RELRO', have_full_relro, bool_yn: true, section: 'Hardening')
