curl = find_program('', required: false)

if get_option('module-remote') != 'disabled' and get_option('unit-tests-backends')
  curl = find_program('curl', required: true)
endif

summary('cURL', curl.found(), bool_yn: true, section: 'Programs')
