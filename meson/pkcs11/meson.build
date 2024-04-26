opt_pkcs11 = get_option('experimental-pkcs11')
dep_pkcs11 = dependency('', required: false)
have_p11kit1 = false
have_p11kit1_v2 = false

if opt_pkcs11.enabled() or opt_pkcs11.auto()
  dep_pkcs11 = dependency('p11-kit-1', required: opt_pkcs11)
  have_p11kit1 = dep_pkcs11.found()

  prog = fs.read('p11_kit_module_for_name.cc')
  have_p11kit1_v2 = cxx.links(prog, dependencies: dep_pkcs11, name: 'we can link to p11kit1')
endif

conf.set('HAVE_P11KIT1', have_p11kit1, description: 'Have p11-kit-1')
conf.set('HAVE_P11KIT1_V2', have_p11kit1_v2, description: 'Have p11-kit-1 0.20 or newer')
