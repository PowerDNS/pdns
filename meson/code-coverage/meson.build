coverage = get_option('b_coverage')
clang_coverage = get_option('clang-coverage-format')

if coverage or clang_coverage
  add_project_arguments('-DCOVERAGE', language: ['c', 'cpp'])

  if get_option('buildtype') != 'debug'
    warning('Coverage is enabled, using `builtype=debug` would produce better reports')
  endif

  if cxx.has_argument('-U_FORTIFY_SOURCE')
    add_project_arguments('-U_FORTIFY_SOURCE', language: ['c', 'cpp'])
  endif

endif

if coverage
  if get_option('clang-coverage-format')
    error('b_coverage and clang-coverage-format cannot be enabled at the same time')
  endif
  summary('Code Coverage', coverage, bool_yn: true, section: 'Configuration')
else
  if get_option('clang-coverage-format')
    # let's see if the clang++ specific format is supported,
    # as it has a much lower overhead and is more accurate,
    # see https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
    add_project_arguments('-DCLANG_COVERAGE', '-fprofile-instr-generate', '-fcoverage-mapping', language: ['c', 'cpp'])
    add_project_link_arguments('-fprofile-instr-generate', '-fcoverage-mapping', language: ['c', 'cpp'])
    summary('Code Coverage (clang format)', true, bool_yn: true, section: 'Configuration')
  endif
endif
