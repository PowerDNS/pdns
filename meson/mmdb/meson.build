dep_mmdb = dependency('', required: false)

if get_option('module-geoip') != 'disabled'
  dep_mmdb = dependency('libmaxminddb', required: false)
endif

conf.set('HAVE_MMDB', dep_mmdb.found(), description: 'MaxMindDB')

summary('MaxMindDB', dep_mmdb.found(), bool_yn: true, section: 'GeoIP Backend')

if dep_mmdb.found()
  summary('MaxMindDB Name', dep_mmdb.name(), section: 'GeoIP Backend')
  summary('MaxMindDB Version', dep_mmdb.version(), section: 'GeoIP Backend')
endif
