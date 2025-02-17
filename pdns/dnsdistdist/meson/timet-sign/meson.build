fs = import('fs')

prog = fs.read('timet_sign.cc')
timet_signed = cxx.compiles(prog, name: 'time_t is signed')

if not timet_signed
  error('time_t is unsigned, PowerDNS code relies on it being signed')
endif

summary('Signed time_t', timet_signed, bool_yn: true, section: 'System')
