sources = [
  'ldapauthenticator.cc',
  'ldapbackend.cc',
  'ldaputils.cc',
  'master.cc',
  'native.cc',
  'powerldap.cc',
]

extras = [
  'exceptions.hh',
  'ldapauthenticator.hh',
  'ldapauthenticator_p.hh',
  'ldapbackend.hh',
  'ldaputils.hh',
  'powerldap.hh',
  'utils.hh',

  'dnsdomain2.schema',
  'pdns-domaininfo.schema',
]

deps = [dep_pdns, dep_libcrypto, dep_ldap]

lib = static_library(
  module_backend_name,
  sources,
  dependencies: deps,
  extra_files: extras,
)

dep_name = 'dep_' + module_backend_name
set_variable(dep_name, dependency('', required: false))
if module_opt == 'static'
  dep = declare_dependency(link_with: lib)
  set_variable(dep_name, dep)
else
  shared_module(module_backend_name, link_with: lib)
endif
