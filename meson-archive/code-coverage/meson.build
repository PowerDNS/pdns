# Code coverage

code_coverage = get_option('code-coverage')

if code_coverage
  args = ['-U_FORTIFY_SOURCE', '-g', '-O0', '-fprofile-arcs', '-ftest-coverage']

  foreach arg: args
    if not cxx.has_argument(arg)
      error('Compiler does not support ' + arg + ', which is needed for code coverage')
      break
    endif
  endforeach

  add_global_arguments(args, language: ['c', 'cpp'])
endif

summary('Code Coverage', code_coverage, bool_yn: true, section: 'Configuration')
