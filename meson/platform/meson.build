# Platform detection
# Inputs: deps conf system

platforms = [
  ['linux',   [['HAVE_LINUX',   'We are on Linux']], [], []],
  ['darwin',  [['HAVE_DARWIN',  'We are on Darwin/MacOS']], [], ['__APPLE_USE_RFC_3542', '_XOPEN_SOURCE', '_DARWIN_C_SOURCE'], []],
  ['openbsd', [['HAVE_OPENBSD', 'We are on OpenBSD']], [], []],
  ['freebsd', [['HAVE_FREEBSD', 'We are on FreeBSD']], [], []],
  ['sunos',   [['HAVE_SOLARIS', 'We are on Solaris/SunOS'],
               ['NEED_POSIX_TYPEDEF', 'POSIX typedefs need to be defined'],
               ['NEED_INET_NTOP_PROTO', 'OS is so broken that it needs an additional prototype']],
   ['_REENTRANT'], ['posix4']],
]

foreach platform: platforms
  name = platform[0]
  defines = platform[1]
  args = platform[2]
  libs = platform[3]

  if system == name
    platform_defines = []
    foreach define: defines
      define_name = define[0]
      define_desc = define[1]
      conf.set10(define_name, true, description: define_desc)
      platform_defines += define[0]
    endforeach

    foreach arg: args
      add_project_arguments(['-D' + arg], language: 'cpp')
    endforeach

    foreach lib: libs
      deps += cxx.find_library(lib, required: true)
    endforeach

    summary('Defines', ' '.join(platform_defines), section: 'System')

    break
  endif
endforeach
