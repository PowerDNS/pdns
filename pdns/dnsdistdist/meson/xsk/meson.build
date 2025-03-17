opt_xsk = get_option('xsk')
if opt_xsk.allowed()
  dep_libbpf = dependency('libbpf', required: opt_xsk.enabled())
  dep_libxdp = dependency('libxdp', required: opt_xsk.enabled())

  if dep_libbpf.found() and dep_libxdp.found()
    has = cxx.has_function('bpf_xdp_query', dependencies: dep_libbpf)
    conf.set('HAVE_BPF_XDP_QUERY', has, description: 'Have BPF bpf_xdp_query')
  endif

  conf.set('HAVE_BPF', dep_libbpf.found(), description: 'BPF library')
  conf.set('HAVE_XDP', dep_libxdp.found(), description: 'XDP library')
  conf.set('HAVE_XSK', dep_libbpf.found() and dep_libxdp.found(), description: 'AF_XDP (XSK) support enabled')
  summary('AF_XDP (XSK)', dep_libbpf.found() and dep_libxdp.found(), bool_yn: true, section: 'XSK')
else
  dep_libbpf = declare_dependency()
  dep_libxdp = declare_dependency()
endif
