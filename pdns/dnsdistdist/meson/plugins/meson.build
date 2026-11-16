if target_machine.system() != 'darwin'
  add_project_link_arguments('-Wl,--export-dynamic-symbol=*registerNewPlugin*', language: ['c', 'cpp'])
else
  add_project_link_arguments('-rdynamic', language: ['c', 'cpp'])
endif
