opt_xsk = get_option('xsk')
if opt_xsk.allowed()
  dep_libbpf = dependency('libbpf', required: opt_xsk)
  dep_libxdp = dependency('libxdp', required: opt_xsk)

  conf.set('HAVE_BPF', dep_libbpf.found(), description: 'BPF library')
  conf.set('HAVE_XDP', dep_libxdp.found(), description: 'XDP library')
  conf.set('HAVE_XSK', dep_libbpf.found() and dep_libxdp.found(), description: 'AF_XDP (XSK) support enabled')
  summary('AF_XDP (XSK)', dep_libbpf.found() and dep_libxdp.found(), bool_yn: true, section: 'XSK')
else
  dep_libpf = declare_dependency()
  dep_libxdp = declare_dependency()
endif
