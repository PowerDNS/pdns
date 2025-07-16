if get_option('ebpf').allowed()
  if cxx.check_header('linux/bpf.h') and cxx.get_define('SO_ATTACH_BPF', prefix: '#include "sys/socket.h"') != ''
     conf.set('HAVE_EBPF', true, description: 'eBPF')
     summary('eBPF', true, bool_yn: true, section: 'eBPF')
  else
     summary('eBPF', false, bool_yn: true, section: 'eBPF')
  endif
endif
