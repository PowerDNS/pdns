dep_yaml_cpp = dependency('yaml-cpp', version: '>= 0.5', required: true)

summary('YAML-CPP', dep_yaml_cpp.found(), bool_yn: true, section: 'GeoIP Backend')
if dep_yaml_cpp.found()
  summary('YAML-CPP Name', dep_yaml_cpp.name(), section: 'GeoIP Backend')
  summary('YAML-CPP Version', dep_yaml_cpp.version(), section: 'GeoIP Backend')
endif
