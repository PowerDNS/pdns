opt_ixfrdist = get_option('tools-ixfrdist')
dep_ixfrdist = dependency('', required: false)

if opt_ixfrdist
  dep_yaml_cpp = dependency('yaml-cpp', version: '>= 0.5', required: true)
  dep_ixfrdist = declare_dependency(dependencies: dep_yaml_cpp)
endif

conf.set('IXFRDIST', dep_ixfrdist.found(), description: 'Whether to build ixfrdist')
summary('Build `ixfrdist`', dep_ixfrdist.found(), bool_yn: true, section: 'Configuration')
