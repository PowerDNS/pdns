have_relro = true
variants = [
  '-Wl,-z,relro',
  '-Wl,-z,now',
]

foreach variant: variants
  if cxx.has_link_argument(variant)
    hardening_features += [[true, 'RELRO (' + variant + ')']]
    add_project_link_arguments(variant, language: ['c', 'cpp'])
  else
    have_relro = false
  endif
endforeach

summary('RELRO', have_relro, bool_yn: true, section: 'Hardening')
