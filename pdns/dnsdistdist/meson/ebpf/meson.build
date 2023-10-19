if get_option('ebpf').allowed()
  if cxx.check_header('linux/bpf.h') and cxx.get_define('SO_ATTACH_BPF', prefix: '#include "sys/socket.h"') != ''
     conf.set('HAVE_EBPF', true, description: 'eBPF')
     summary('eBPF', true, bool_yn: true, section: 'eBPF')
     has = cxx.has_header_symbol('linux/bpf.h', 'BPF_FUNC_get_prandom_u32')
     conf.set('HAVE_BPF_FUNC_get_prandom_u32', has, description: 'have BPF_FUNC_get_prandom_u32 in BPF')
  else
     summary('eBPF', false, bool_yn: true, section: 'eBPF')
  endif
endif
