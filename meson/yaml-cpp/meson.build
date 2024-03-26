dep_yaml_cpp = dependency('', required: false)

if get_option('module-geoip') != 'disabled' or get_option('tools-ixfrdist')
  dep_yaml_cpp = dependency('yaml-cpp', version: '>= 0.5', required: true)
endif

if get_option('module-geoip') != 'disabled'
  summary('YAML-CPP', dep_yaml_cpp.found(), bool_yn: true, section: 'GeoIP Backend')
  if dep_yaml_cpp.found()
    summary('YAML-CPP Name', dep_yaml_cpp.name(), section: 'GeoIP Backend')
    summary('YAML-CPP Version', dep_yaml_cpp.version(), section: 'GeoIP Backend')
  endif
endif

if get_option('tools-ixfrdist')
  summary('YAML-CPP', dep_yaml_cpp.found(), bool_yn: true, section: 'IXFRDist')
  if dep_yaml_cpp.found()
    summary('YAML-CPP Name', dep_yaml_cpp.name(), section: 'IXFRDist')
    summary('YAML-CPP Version', dep_yaml_cpp.version(), section: 'IXFRDist')
  endif
endif
