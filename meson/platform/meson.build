platforms = [
  ['linux',   [['HAVE_LINUX',   'On Linux']], [], []],
  ['darwin',  [['HAVE_DARWIN',  'On Darwin/MacOS']], [], ['__APPLE_USE_RFC_3542', '_XOPEN_SOURCE', '_DARWIN_C_SOURCE'], []],
  ['openbsd', [['HAVE_OPENBSD', 'On OpenBSD']], [], []],
  ['freebsd', [['HAVE_FREEBSD', 'On FreeBSD']], [], []],
  ['sunos',   [['HAVE_SOLARIS', 'On Solaris/SunOS'],
               ['NEED_POSIX_TYPEDEF', 'POSIX typedefs need to be defined'],
               ['NEED_INET_NTOP_PROTO', 'OS is so broken that it needs an additional prototype']],
   ['_REENTRANT'], ['posix4']],
]

platform_deps = []
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
      conf.set(define_name, true, description: define_desc)
      platform_defines += define[0]
    endforeach

    foreach arg: args
      add_global_arguments('-D' + arg, language: ['c', 'cpp'])
    endforeach

    foreach lib: libs
      platform_deps += cxx.find_library(lib, required: true)
    endforeach

    summary('Platform Defines', platform_defines, section: 'System')

    break
  endif
endforeach

dep_platform = declare_dependency(
  dependencies: platform_deps,
)
