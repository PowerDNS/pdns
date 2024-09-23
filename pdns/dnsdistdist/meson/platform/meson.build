platforms = [
  {
    'name': 'linux',
    'config-defines': [{ 'name': 'HAVE_LINUX', 'description': 'On Linux' }],
  },
  {
    'name': 'darwin',
    'config-defines': [{ 'name': 'HAVE_DARWIN', 'description': 'On Darwin/MacOS' }],
    'cmdline-defines': ['__APPLE_USE_RFC_3542', '_XOPEN_SOURCE', '_DARWIN_C_SOURCE'],
  },
  {
    'name': 'openbsd',
    'config-defines': [{ 'name': 'HAVE_OPENBSD', 'description': 'On OpenBSD' }],
  },
  {
    'name': 'freebsd',
    'config-defines': [{ 'name': 'HAVE_FREEBSD', 'description': 'On FreeBSD' }],
  },
  {
    'name': 'sunos',
    'config-defines': [
      { 'name': 'HAVE_SOLARIS', 'description': 'On Solaris/SunOS' },
      { 'name': 'NEED_POSIX_TYPEDEF', 'description': 'POSIX typedefs need to be defined' },
      { 'name': 'NEED_INET_NTOP_PROTO', 'description': 'OS is so broken that it needs an additional prototype' },
    ],
    'cmdline-defines': ['_REENTRANT'],
    'libraries': ['posix4'],
  },
]

platform_deps = []

foreach platform: platforms
  name = platform['name']
  set_variable('have_' + name, system == name)

  config_defines = 'config-defines' in platform ? platform['config-defines'] : []
  cmdline_defines = 'cmdline-defines' in platform ? platform['cmdline-defines'] : []
  libraries = 'libraries' in platform ? platform['libraries'] : []

  if system == name
    platform_defines = []
    foreach define: config_defines
      define_name = define['name']
      define_desc = define['description']
      conf.set(define_name, true, description: define_desc)
      platform_defines += define_name
    endforeach

    foreach cmdline_define: cmdline_defines
      add_project_arguments('-D' + cmdline_define, language: ['c', 'cpp'])
    endforeach

    foreach library: libraries
      platform_deps += cxx.find_library(library, required: true)
    endforeach

    summary('Platform Defines', platform_defines, section: 'System')
  endif
endforeach

dep_platform = declare_dependency(
  dependencies: platform_deps,
)
