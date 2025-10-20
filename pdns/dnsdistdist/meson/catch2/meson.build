dep_catch2 = dependency('', required: false)
if get_option('benchmark')
  dep_catch2 = dependency('catch2-with-main', version: '>=3',  required: true)
  summary('Catch2', dep_catch2.found(), bool_yn: true, section: 'Configuration')
endif
