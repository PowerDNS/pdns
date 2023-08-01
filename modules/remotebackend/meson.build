sources = [
  # TODO Change this into a libpdns library
  '../../pdns/arguments.cc',
  '../../pdns/auth-packetcache.cc',
  '../../pdns/auth-querycache.cc',
  '../../pdns/auth-zonecache.cc',
  '../../pdns/base32.cc',
  '../../pdns/base64.cc',
  '../../pdns/dns.cc',
  '../../pdns/dns_random_urandom.cc',
  '../../pdns/dnsbackend.cc',
  '../../pdns/dnslabeltext.cc',
  '../../pdns/dnsname.cc',
  '../../pdns/dnspacket.cc',
  '../../pdns/dnsparser.cc',
  '../../pdns/dnsrecords.cc',
  '../../pdns/dnssecinfra.cc',
  '../../pdns/dnswriter.cc',
  '../../pdns/ednscookies.cc',
  '../../pdns/ednsoptions.cc',
  '../../pdns/ednssubnet.cc',
  '../../pdns/gss_context.cc',
  '../../pdns/iputils.cc',
  '../../pdns/json.cc',
  '../../pdns/logger.cc',
  '../../pdns/misc.cc',
  '../../pdns/nameserver.cc',
  '../../pdns/nsecrecords.cc',
  '../../pdns/qtype.cc',
  '../../pdns/rcpgenerator.cc',
  '../../pdns/shuffle.cc',
  '../../pdns/sillyrecords.cc',
  '../../pdns/statbag.cc',
  '../../pdns/svc-records.cc',
  '../../pdns/ueberbackend.cc',
  '../../pdns/unix_utility.cc',
  'httpconnector.cc',
  'pipeconnector.cc',
  'remotebackend.cc',
  'unixconnector.cc',
  'zmqconnector.cc',
]

if remote_module
  static_library('remotebackend', sources)
endif

if remote_dyn_module
endif
