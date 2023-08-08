# Stack Protector
# Inputs: hardening_features

support_stack_protector = cxx.has_argument('-fstack-protector')

if support_stack_protector
  add_global_arguments('-fstack-protector', language: ['cpp'])
endif

hardening_features += [[support_stack_protector, 'Stack Protector']]
summary('Stack Protector', support_stack_protector, bool_yn: true, section: 'Hardening')
