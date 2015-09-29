#1/bin/bash
regression_tests() {
  cd regression-tests
  touch tests/verify-dnssec-zone/allow-missing
  touch tests/verify-dnssec-zone/skip.nsec3 # some (travis) tools in this test are unable to handle nsec3 zones
  touch tests/verify-dnssec-zone/skip.optout
  export geoipregion=oc geoipregionip=1.2.3.4
  echo \
  "./timestamp ./start-test-stop 5300 bind-both 2>&1
  ./timestamp ./start-test-stop 5350 bind-dnssec-both 2>&1
  ./timestamp ./start-test-stop 5400 bind-dnssec-pkcs11 2>&1
  ./timestamp ./start-test-stop 5450 bind-dnssec-nsec3-both 2>&1
  ./timestamp ./start-test-stop 5500 bind-dnssec-nsec3-optout-both 2>&1
  ./timestamp ./start-test-stop 5550 bind-dnssec-nsec3-narrow 2>&1
  ./timestamp ./start-test-stop 5600 bind-hybrid-nsec3 2>&1
  ./timestamp ./start-test-stop 5650 geoipbackend 2>&1
  ./timestamp ./start-test-stop 5700 geoipbackend-nsec3-narrow 2>&1
  ./timestamp ./start-test-stop 5750 gmysql-nodnssec-both 2>&1
  ./timestamp ./start-test-stop 5800 gmysql-both 2>&1
  ./timestamp ./start-test-stop 5850 gmysql-nsec3-both 2>&1
  ./timestamp ./start-test-stop 5900 gmysql-nsec3-optout-both 2>&1
  ./timestamp ./start-test-stop 5950 gmysql-nsec3-narrow 2>&1
  ./timestamp ./start-test-stop 6000 gpgsql-nodnssec-both 2>&1
  ./timestamp ./start-test-stop 6050 gpgsql-both 2>&1
  ./timestamp ./start-test-stop 6100 gpgsql-nsec3-both 2>&1
  ./timestamp ./start-test-stop 6150 gpgsql-nsec3-optout-both 2>&1
  ./timestamp ./start-test-stop 6200 gpgsql-nsec3-narrow 2>&1
  ./timestamp ./start-test-stop 6250 gsqlite3-nodnssec-both 2>&1
  ./timestamp ./start-test-stop 6300 gsqlite3-both 2>&1
  ./timestamp ./start-test-stop 6350 gsqlite3-nsec3-both 2>&1
  ./timestamp ./start-test-stop 6400 gsqlite3-nsec3-optout-both 2>&1
  ./timestamp ./start-test-stop 6450 gsqlite3-nsec3-narrow 2>&1
#DNSName ./timestamp ./start-test-stop 6500 lmdb-nodnssec 2>&1
  ./timestamp ./start-test-stop 6550 mydns 2>&1
  ./timestamp ./start-test-stop 6600 opendbx-sqlite3 2>&1
  travis_retry ./timestamp timeout 120s ./start-test-stop 6650 remotebackend-pipe 2>&1
  travis_retry ./timestamp timeout 120s ./start-test-stop 6700 remotebackend-pipe-dnssec 2>&1
  travis_retry ./timestamp timeout 120s ./start-test-stop 6750 remotebackend-unix 2>&1
  travis_retry ./timestamp timeout 120s ./start-test-stop 6800 remotebackend-unix-dnssec 2>&1
  travis_retry ./timestamp timeout 120s ./start-test-stop 6850 remotebackend-http 2>&1
  travis_retry ./timestamp timeout 120s ./start-test-stop 6900 remotebackend-http-dnssec 2>&1
  travis_retry ./timestamp timeout 120s ./start-test-stop 6950 remotebackend-zeromq 2>&1
  travis_retry ./timestamp timeout 120s ./start-test-stop 7000 remotebackend-zeromq-dnssec 2>&1
  ./timestamp ./start-test-stop 7050 tinydns 2>&1" | parallel
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
