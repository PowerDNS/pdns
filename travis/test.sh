#1/bin/sh
regression_tests() {
  cd regression-tests
  touch tests/verify-dnssec-zone/allow-missing
  touch tests/verify-dnssec-zone/skip.nsec3 # some (travis) tools in this test are unable to handle nsec3 zones
  touch tests/verify-dnssec-zone/skip.optout
  export geoipregion=oc geoipregionip=1.2.3.4
  ./timestamp ./start-test-stop 5300 bind-both
  ./timestamp ./start-test-stop 5300 bind-dnssec-both
  ./timestamp ./start-test-stop 5300 bind-dnssec-pkcs11
  ./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-both
  ./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-optout-both
  ./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-narrow
  ./timestamp ./start-test-stop 5300 bind-hybrid-nsec3
  ./timestamp ./start-test-stop 5300 geoipbackend
  ./timestamp ./start-test-stop 5300 geoipbackend-nsec3-narrow
  ./timestamp ./start-test-stop 5300 gmysql-nodnssec-both
  ./timestamp ./start-test-stop 5300 gmysql-both
  ./timestamp ./start-test-stop 5300 gmysql-nsec3-both
  ./timestamp ./start-test-stop 5300 gmysql-nsec3-optout-both
  ./timestamp ./start-test-stop 5300 gmysql-nsec3-narrow
  ./timestamp ./start-test-stop 5300 gpgsql-nodnssec-both
  ./timestamp ./start-test-stop 5300 gpgsql-both
  ./timestamp ./start-test-stop 5300 gpgsql-nsec3-both
  ./timestamp ./start-test-stop 5300 gpgsql-nsec3-optout-both
  ./timestamp ./start-test-stop 5300 gpgsql-nsec3-narrow
  ./timestamp ./start-test-stop 5300 gsqlite3-nodnssec-both
  ./timestamp ./start-test-stop 5300 gsqlite3-both
  ./timestamp ./start-test-stop 5300 gsqlite3-nsec3-both
  ./timestamp ./start-test-stop 5300 gsqlite3-nsec3-optout-both
  ./timestamp ./start-test-stop 5300 gsqlite3-nsec3-narrow
#DNSName ./timestamp ./start-test-stop 5300 lmdb-nodnssec
  ./timestamp ./start-test-stop 5300 mydns
  ./timestamp ./start-test-stop 5300 opendbx-sqlite3
  travis_retry ./timestamp timeout 120s ./start-test-stop 5300 remotebackend-pipe
  travis_retry ./timestamp timeout 120s ./start-test-stop 5300 remotebackend-pipe-dnssec
  travis_retry ./timestamp timeout 120s ./start-test-stop 5300 remotebackend-unix
  travis_retry ./timestamp timeout 120s ./start-test-stop 5300 remotebackend-unix-dnssec
  travis_retry ./timestamp timeout 120s ./start-test-stop 5300 remotebackend-http
  travis_retry ./timestamp timeout 120s ./start-test-stop 5300 remotebackend-http-dnssec
  travis_retry ./timestamp timeout 120s ./start-test-stop 5300 remotebackend-zeromq
  travis_retry ./timestamp timeout 120s ./start-test-stop 5300 remotebackend-zeromq-dnssec
  ./timestamp ./start-test-stop 5300 tinydns
  rm -f tests/verify-dnssec-zone/allow-missing
  rm -f tests/verify-dnssec-zone/skip.nsec3
  rm -f tests/verify-dnssec-zone/skip.optout
  THRESHOLD=90 TRACE=no ./timestamp ./recursor-test 5300
  cd ..
}

regression_tests_recursor() {
  cd regression-tests.recursor
  cp vars.sample vars
  if [ "$TRAVIS_OS_NAME" = 'osx' ]; then
    perl -i -pe 's/exec authbind //' vars
    USE_SUDO='sudo'
  fi
  ./config.sh
  $USE_SUDO ./start.sh
  sleep 3
  svstat configs/*
  ./runtests
  #DNSName  test ! -s ./failed_tests
  $USE_SUDO ./stop.sh
  sleep 3
  ./clean.sh
  cd ..
}

regression_tests_nobackend() {
  cd regression-tests.nobackend/
  ./runtests
  test ! -s ./failed_tests
  cd ..
}

regressiont_tests_api() {
#DNSName cd regression-tests.api
#DNSName ./runtests authoritative
#DNSName ./runtests recursor
#DNSName cd ..
  return 0
}

test_algos() {
  cd pdns
  ./pdnssec test-algorithms
  cd ..
}

clean_git() {
  if ! $(git status | grep -q clean); then
    git status
    return 1
  fi
}


regression_tests
test_algos
regression_tests_recursor
regression_tests_nobackend
clean_git
