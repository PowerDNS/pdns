coverage = get_option('b_coverage')

if coverage
  add_project_arguments('-DCOVERAGE', language: ['c', 'cpp'])

  if get_option('buildtype') != 'debug'
    warning('Coverage is enabled, using `builtype=debug` would produce better reports')
  endif

  if cxx.has_argument('-U_FORTIFY_SOURCE')
    add_project_arguments('-U_FORTIFY_SOURCE', language: ['c', 'cpp'])
  endif
endif

summary('Code Coverage', coverage, bool_yn: true, section: 'Configuration')
