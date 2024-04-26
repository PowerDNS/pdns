dep_geoip = dependency('', required: false)

if get_option('module-geoip') != 'disabled'
dep_geoip = dependency('geoip', required: false)
endif

conf.set('HAVE_GEOIP', dep_geoip.found(), description: 'GeoIP')

summary('GeoIP', dep_geoip.found(), bool_yn: true, section: 'GeoIP Backend')

if dep_geoip.found()
  summary('GeoIP Name', dep_geoip.name(), section: 'GeoIP Backend')
  summary('GeoIP Version', dep_geoip.version(), section: 'GeoIP Backend')
endif
