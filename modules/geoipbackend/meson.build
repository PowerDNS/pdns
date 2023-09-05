# Detect mmap
have_mmap = cxx.has_function('mmap')
mman_h = cxx.has_header('sys/mman.h', required: false)
if not have_mmap
  have_mmap = mman_h and cxx.has_function('mmap', prefix: '''#include <sys/mman.h>''')
endif
conf.set('HAVE_MMAP', have_mmap, description: 'GeoIP Backend: mmap')
summary('Have <sys/mman.h>', mman_h, bool_yn: true, section: 'GeoIP Backend')
summary('mmap', have_mmap, bool_yn: true, section: 'GeoIP Backend')

# Detect GeoIP
dep_geoip = dependency('geoip', required: false)
conf.set('HAVE_GEOIP', dep_geoip.found(), description: 'GeoIP Backend: GeoIP Library')
summary('GeoIP', dep_geoip.found(), bool_yn: true, section: 'GeoIP Backend')
if dep_geoip.found()
  summary('GeoIP Name', dep_geoip.name(), section: 'GeoIP Backend')
  summary('GeoIP Version', dep_geoip.version(), section: 'GeoIP Backend')
endif

# Detect MaxMindDB
dep_mmdb = dependency('libmaxminddb', required: false)
conf.set('HAVE_MMDB', dep_mmdb.found(), description: 'GeoIP Backend: MaxMindDB Library')
summary('MaxMindDB', dep_mmdb.found(), bool_yn: true, section: 'GeoIP Backend')
if dep_mmdb.found()
  summary('MaxMindDB Name', dep_mmdb.name(), section: 'GeoIP Backend')
  summary('MaxMindDB Version', dep_mmdb.version(), section: 'GeoIP Backend')
endif

# Detect YAML-cpp
dep_yaml_cpp = dependency('yaml-cpp', version: '>= 0.5', required: true)
summary('YAML-CPP', dep_yaml_cpp.found(), bool_yn: true, section: 'GeoIP Backend')
summary('YAML-CPP Name', dep_yaml_cpp.name(), section: 'GeoIP Backend')
summary('YAML-CPP Version', dep_yaml_cpp.version(), section: 'GeoIP Backend')

# Build the backend
sources = [
  'geoipbackend.cc',
  'geoipinterface-dat.cc',
  'geoipinterface-mmdb.cc',
  'geoipinterface.cc',
]

extras = [
  'geoipbackend.hh',
  'geoipinterface.hh',
]

module_deps = [deps, dep_geoip, dep_mmdb, dep_yaml_cpp]

lib = static_library(
  module_backend_name,
  sources,
  dependencies: module_deps,
  extra_files: extras,
)

dep_name = 'dep_' + module_backend_name
set_variable(dep_name, dependency('', required: false))
if module_opt == 'static'
  dep = declare_dependency(link_whole: lib)
  set_variable(dep_name, dep)
else
  shared_module(module_backend_name, link_whole: lib)
endif
