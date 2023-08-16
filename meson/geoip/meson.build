dep_geoip = dependency('geoip', required: true)
dep_libmmdb = dependency('libmaxminddb', required: true)
dep_yaml_cpp = dependency('yaml-cpp', version: '>= 0.5', required: true)

conf.set('HAVE_GEOIP', dep_geoip.found(), description: 'GeoIP')
conf.set('HAVE_MMDB', dep_mmdb.found(), description: 'MaxMindDB')

summary('GeoIP', dep_geoip.found(), bool_yn: true, section: 'GeoIP')
summary('GeoIP Name', dep_geoip.name(), section: 'GeoIP')
summary('GeoIP Version', dep_geoip.version(), section: 'GeoIP')

summary('MaxMindDB', dep_mmdb.found(), bool_yn: true, section: 'GeoIP')
summary('MaxMindDB Name', dep_mmdb.name(), section: 'GeoIP')
summary('MaxMindDB Version', dep_mmdb.version(), section: 'GeoIP')

summary('YAML-CPP', dep_yaml_cpp.found(), bool_yn: true, section: 'GeoIP')
summary('YAML-CPP Name', dep_yaml_cpp.name(), section: 'GeoIP')
summary('YAML-CPP Version', dep_yaml_cpp.version(), section: 'GeoIP')

dep_geoip = declare_dependency(
  dependencies: [
    dep_geoip,
    dep_mmdb,
    dep_yaml_cpp,
  ],
)
