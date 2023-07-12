# Stack Protector
# Inputs: hardening_features deps

support_stack_protector = cxx.has_argument('-fstack-protector')

if support_stack_protector
  dep_sp = declare_dependency(compile_args: ['-fstack-protector'])
  deps += dep_sp
endif

hardening_features += [[support_stack_protector, 'Stack Protector']]
summary('Stack Protector', support_stack_protector, bool_yn: true, section: 'Hardening')
