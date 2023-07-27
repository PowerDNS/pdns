# Ixfrdist
# Inputs: deps conf

opt_ixfrdist = get_option('ixfrdist')
deps += dependency('yaml-cpp', version: '>= 0.5', required: opt_ixfrdist)
conf.set10('IXFRDIST', opt_ixfrdist, description: 'Whether to build ixfrdist')
summary('Build `ixfrdist`', opt_ixfrdist, section: 'Configuration')
