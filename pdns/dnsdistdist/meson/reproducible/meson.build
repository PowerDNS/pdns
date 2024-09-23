opt_repro = get_option('reproducible')
conf.set('REPRODUCIBLE', opt_repro, description: 'Reproducible builds')
summary('Reproducible Builds', opt_repro, bool_yn: true, section: 'Reproducible Builds')

if not opt_repro
  id_prog = find_program('id', required: opt_repro)
  id_prog_res = run_command(id_prog, '-u', '-n', check: true)
  build_user = id_prog_res.stdout().strip()

  build_host = ''
  hostname_prog = find_program('hostname', required: opt_repro)
  build_system = build_machine.system()
  if build_system == 'sunos' or build_system == 'openbsd'
    domainname_prog = find_program('domainname', required: opt_repro)

    hostname_prog_res = run_command(hostname_prog, check: true)
    domainname_prog_res = run_command(domainname_prog, check: true)

    build_host_hostname = hostname_prog_res.stdout().strip()
    build_host_domainname = domainname_prog_res.stdout().strip()

    build_host = build_host_hostname + '.' + build_host_domainname
  else
    cmds = [
      [hostname_prog, '-f'],
      [hostname_prog],
      ['echo', '\'localhost\''],
    ]

    found = false
    foreach cmd: cmds
      res = run_command(cmd, check: false)
      if res.returncode() == 0
        build_host = res.stdout().strip()
        found = true
        break
      endif
    endforeach

    if not found
      error('Reproducible builds requested but could not figure out a build host string on ' + build_system)
    endif
  endif

  build_host = build_user + '@' + build_host
  conf.set_quoted('BUILD_HOST', build_host, description: 'User and host who built PowerDNS')
  summary('Build Host', build_host, section: 'Reproducible Builds')
endif
