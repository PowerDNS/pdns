opt_cuckoo = get_option('cuckoo')

conf.set(
  'HAVE_CUCKOO',
  opt_cuckoo.allowed(),
  description: 'Whether we have cuckoo filter support',
)

summary('Cuckoo filter', opt_cuckoo, bool_yn: true, section: 'Cuckoo filter')
