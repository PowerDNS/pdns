# GeoIP
# Outputs: deps_geoip

deps_geoip  = []
deps_geoip += dependency('geoip', required: true)
deps_geoip += dependency('libmaxminddb', required: true)
deps_geoip += dependency('yaml-cpp', version: '>= 0.5', required: true)

conf.set10('HAVE_GEOIP', deps_geoip[0].found(), description: 'Whether we have GeoIP')
conf.set10('HAVE_MMDB', deps_geoip[1].found(), description: 'Whether we have MaxMindDB')
summary('GeoIP', deps_geoip[0].found(), bool_yn: true, section: 'Configuration')
