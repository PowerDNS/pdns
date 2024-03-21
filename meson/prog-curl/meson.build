require_curl = get_option('module-remote') != 'disabled' and get_option('unit-tests-backends')
curl = find_program('curl', required: require_curl)
summary('cURL', curl.found(), bool_yn: true, section: 'Programs')
