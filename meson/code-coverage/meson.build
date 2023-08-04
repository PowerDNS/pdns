# Code coverage
# Inputs: deps

code_coverage_deps = []
code_coverage = get_option('code-coverage')

if code_coverage
  args = ['-U_FORTIFY_SOURCE', '-g', '-O0', '-fprofile-arcs', '-ftest-coverage']

  foreach arg: args
    if not cxx.has_argument(arg)
      error('Compiler does not support ' + arg + ', which is needed for code coverage')
      break
    endif

    code_coverage_deps += declare_dependency(compile_args: [arg])
  endforeach
endif

summary('Code Coverage', code_coverage, bool_yn: true, section: 'Configuration')
