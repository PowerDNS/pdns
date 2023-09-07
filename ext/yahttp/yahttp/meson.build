prefix = '''
#include <sys/types.h>
#include <time.h>
'''

has = cxx.has_member('struct tm', 'tm_gmtoff', prefix: prefix)
conf.set('HAVE_TM_GMTOFF', has, description: 'Whether tm_gmtoff is available')
summary('tm_gmtoff', has, bool_yn: true, section: 'YaHTTP')

lib_yahttp = static_library(
  'yahttp',
  'reqresp.cpp',
  'router.cpp',
  extra_files: [
    'cookie.hpp',
    'exception.hpp',
    'reqresp.hpp',
    'router.hpp',
    'url.hpp',
    'utility.hpp',
    'yahttp-config.h',
    'yahttp.hpp',
  ],
  cpp_args: '-Wno-overloaded-virtual',
  dependencies: [dep_pdns],
)

dep_yahttp = declare_dependency(
  link_with: lib_yahttp,
  include_directories: include_directories('..'),
)
