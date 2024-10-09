support_stack_smashing_protector = cxx.has_argument('--param=ssp-buffer-size=4')
if support_stack_smashing_protector
  add_project_arguments('--param=ssp-buffer-size=4', language: ['c', 'cpp'])
endif

hardening_features += [[support_stack_smashing_protector, 'Stack Smashing Protection']]
summary('Stack Smashing Protection', support_stack_smashing_protector, bool_yn: true, section: 'Hardening')
if support_stack_smashing_protector
  summary('SSP Buffer Size', 4, section: 'Hardening')
endif
