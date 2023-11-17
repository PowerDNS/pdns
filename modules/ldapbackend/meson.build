sources = [
  'ldapauthenticator.cc',
  'ldapbackend.cc',
  'ldaputils.cc',
  'native.cc',
  'powerldap.cc',
  'primary.cc',
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

module_deps = [deps, dep_ldap]

lib = static_library(
  module_backend_name,
  sources,
  dependencies: module_deps,
  extra_files: extras,
)

dep_name = 'dep_' + module_backend_name
set_variable(dep_name, dependency('', required: false))
if module_opt == 'static'
  dep = declare_dependency(link_whole: lib)
  set_variable(dep_name, dep)
else
  shared_module(module_backend_name, link_whole: lib, name_suffix: 'so')
endif
