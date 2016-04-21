#!/bin/bash

## "upstream" travis functions
ANSI_RED="\033[31;1m"
ANSI_GREEN="\033[32;1m"
ANSI_RESET="\033[0m"
ANSI_CLEAR="\033[0K"

TRAVIS_TEST_RESULT=
TRAVIS_CMD=

function travis_cmd() {
  local assert output display retry timing cmd result

  cmd=$1
  TRAVIS_CMD=$cmd
  shift

  while true; do
    case "$1" in
      --assert)  assert=true; shift ;;
      --echo)    output=true; shift ;;
      --display) display=$2;  shift 2;;
      --retry)   retry=true;  shift ;;
      --timing)  timing=true; shift ;;
      *) break ;;
    esac
  done

  if [[ -n "$timing" ]]; then
    travis_time_start
  fi

  if [[ -n "$output" ]]; then
    echo "\$ ${display:-$cmd}"
  fi

  if [[ -n "$retry" ]]; then
    travis_retry eval "$cmd"
  else
    eval "$cmd"
  fi
  result=$?

  if [[ -n "$timing" ]]; then
    travis_time_finish
  fi

  if [[ -n "$assert" ]]; then
    travis_assert $result
  fi

  return $result
}

travis_time_start() {
  travis_timer_id=$(printf %08x $(( RANDOM * RANDOM )))
  travis_start_time=$(travis_nanoseconds)
  echo -en "travis_time:start:$travis_timer_id\r${ANSI_CLEAR}"
}

travis_time_finish() {
  local result=$?
  travis_end_time=$(travis_nanoseconds)
  local duration=$(($travis_end_time-$travis_start_time))
  echo -en "\ntravis_time:end:$travis_timer_id:start=$travis_start_time,finish=$travis_end_time,duration=$duration\r${ANSI_CLEAR}"
  return $result
}

function travis_nanoseconds() {
  local cmd="date"
  local format="+%s%N"
  local os=$(uname)

  if hash gdate > /dev/null 2>&1; then
    cmd="gdate" # use gdate if available
  elif [[ "$os" = Darwin ]]; then
    format="+%s000000000" # fallback to second precision on darwin (does not support %N)
  fi

  $cmd -u $format
}

travis_assert() {
  local result=${1:-$?}
  if [ $result -ne 0 ]; then
    echo -e "\n${ANSI_RED}The command \"$TRAVIS_CMD\" failed and exited with $result during $TRAVIS_STAGE.${ANSI_RESET}\n\nYour build has been stopped."
    travis_terminate 2
  fi
}

travis_result() {
  local result=$1
  export TRAVIS_TEST_RESULT=$(( ${TRAVIS_TEST_RESULT:-0} | $(($result != 0)) ))

  if [ $result -eq 0 ]; then
    echo -e "\n${ANSI_GREEN}The command \"$TRAVIS_CMD\" exited with $result.${ANSI_RESET}"
  else
    echo -e "\n${ANSI_RED}The command \"$TRAVIS_CMD\" exited with $result.${ANSI_RESET}"
  fi
}

travis_terminate() {
  pkill -9 -P $$ &> /dev/null || true
  exit $1
}

travis_wait() {
  local timeout=$1

  if [[ $timeout =~ ^[0-9]+$ ]]; then
    # looks like an integer, so we assume it's a timeout
    shift
  else
    # default value
    timeout=20
  fi

  local cmd="$@"
  local log_file=travis_wait_$$.log

  $cmd &>$log_file &
  local cmd_pid=$!

  travis_jigger $! $timeout $cmd &
  local jigger_pid=$!
  local result

  {
    wait $cmd_pid 2>/dev/null
    result=$?
    ps -p$jigger_pid &>/dev/null && kill $jigger_pid
  }

  if [ $result -eq 0 ]; then
    echo -e "\n${ANSI_GREEN}The command $cmd exited with $result.${ANSI_RESET}"
  else
    echo -e "\n${ANSI_RED}The command $cmd exited with $result.${ANSI_RESET}"
  fi

  echo -e "\n${ANSI_GREEN}Log:${ANSI_RESET}\n"
  cat $log_file

  return $result
}

travis_jigger() {
  # helper method for travis_wait()
  local cmd_pid=$1
  shift
  local timeout=$1 # in minutes
  shift
  local count=0

  # clear the line
  echo -e "\n"

  while [ $count -lt $timeout ]; do
    count=$(($count + 1))
    echo -ne "Still running ($count of $timeout): $@\r"
    sleep 60
  done

  echo -e "\n${ANSI_RED}Timeout (${timeout} minutes) reached. Terminating \"$@\"${ANSI_RESET}\n"
  kill -9 $cmd_pid
}

travis_retry() {
  local result=0
  local count=1
  while [ $count -le 3 ]; do
    [ $result -ne 0 ] && {
      echo -e "\n${ANSI_RED}The command \"$@\" failed. Retrying, $count of 3.${ANSI_RESET}\n" >&2
    }
    "$@"
    result=$?
    [ $result -eq 0 ] && break
    count=$(($count + 1))
    sleep 1
  done

  [ $count -gt 3 ] && {
    echo -e "\n${ANSI_RED}The command \"$@\" failed 3 times.${ANSI_RESET}\n" >&2
  }

  return $result
}

travis_fold() {
  local action=$1
  local name=$2
  echo -en "travis_fold:${action}:${name}\r${ANSI_CLEAR}"
}

decrypt() {
  echo $1 | base64 -d | openssl rsautl -decrypt -inkey ~/.ssh/id_rsa.repo
}


run() {
  travis_cmd "$1" --echo --assert
}

install_auth() {
  # pkcs11 build requirements
  run "sudo apt-get -qq --no-install-recommends install \
    libp11-kit-dev"

  # geoip-backend
  run "sudo apt-get -qq --no-install-recommends install \
    libgeoip-dev \
    libyaml-cpp-dev"

  # ldap-backend
  run "sudo apt-get -qq --no-install-recommends install \
    libldap-dev"

  # opendbx-backend
  run "sudo apt-get -qq --no-install-recommends install \
    libopendbx1-dev \
    libopendbx1-sqlite3"

  # remote-backend build requirements
  run "sudo apt-get -qq --no-install-recommends install \
    libzmq3-dev"

  # authoritative test requirements / setup
  run "sudo apt-get -qq --no-install-recommends install \
    bind9utils \
    ldnsutils \
    libnet-dns-perl \
    moreutils \
    unbound-host \
    validns \
    default-jre \
    jq"

  run "cd .."
  run "wget http://www.verisignlabs.com/dnssec-tools/packages/jdnssec-tools-0.12.tar.gz"
  run "sudo tar xfz jdnssec-tools-0.12.tar.gz --strip-components=1 -C /"
  run "cd pdns"

  # pkcs11 test requirements / setup
  run "sudo apt-get -qq --no-install-recommends install \
    p11-kit \
    softhsm"
  run "sudo mkdir -p /etc/pkcs11/modules/"
  run "sudo cp -f regression-tests/softhsm.mod /etc/pkcs11/modules/softhsm.module"
  run "sudo cp -f regression-tests/softhsm.conf /etc/softhsm/softhsm.conf"
  run "sudo chmod 0755 /etc/softhsm/"
  run "sudo chmod 0644 /etc/softhsm/softhsm.conf"
  run "sudo chmod 0777 /var/lib/softhsm"
  run "p11-kit -l" # ensure it's ok

  # bind-backend tests requirements
  run "sudo apt-get -qq --no-install-recommends install \
    alien"
  run "cd .."
  run "wget ftp://ftp.nominum.com/pub/nominum/dnsperf/2.0.0.0/dnsperf-2.0.0.0-1-rhel-6-x86_64.tar.gz"
  run "tar xzvf dnsperf-2.0.0.0-1-rhel-6-x86_64.tar.gz"
  run "fakeroot alien --to-deb dnsperf-2.0.0.0-1/dnsperf-2.0.0.0-1.el6.x86_64.rpm"
  run "sudo dpkg -i dnsperf_2.0.0.0-2_amd64.deb"
  run "cd pdns"

  # geoip-backend test requirements / setup
  run "sudo apt-get -qq --no-install-recommends install \
    geoip-database"

  # gmysql-backend test requirements
  run "sudo apt-get -qq --no-install-recommends install \
    mysql-server"

  # godbc-backend test setup
  run echo\ -e\ "[pdns-sqlite3-1]\nDriver = SQLite3\nDatabase = ${PWD}/regression-tests/pdns.sqlite3\n\n[pdns-sqlite3-2]\nDriver = SQLite3\nDatabase = ${PWD}/regression-tests/pdns.sqlite32\n"\ >\ ${HOME}/.odbc.ini

  # ldap-backend test setup
  run "sudo apt-get -qq --no-install-recommends install \
    slapd \
    ldap-utils"
  run "mkdir /tmp/ldap-dns"
  run "pushd /tmp/ldap-dns"
  run 'for schema in /etc/ldap/schema/{core,cosine}.schema ${TRAVIS_BUILD_DIR}/modules/ldapbackend/{dnsdomain2,pdns-domaininfo}.schema ; do echo include $schema ; done > ldap.conf'
  run "mkdir slapd.d"
  run "slaptest -f ldap.conf -F slapd.d"
  run "sudo cp slapd.d/cn=config/cn=schema/cn={*dns*.ldif /etc/ldap/slapd.d/cn=config/cn=schema/"
  run "sudo chown -R openldap:openldap /etc/ldap/slapd.d/"
  run "sudo service slapd restart"
  run "popd"
  run "sudo -u openldap mkdir -p /var/lib/ldap/powerdns"
  run "sudo ldapadd -Y EXTERNAL -H ldapi:/// -f ./modules/ldapbackend/testfiles/add.ldif"

  # remote-backend tests requirements
  run "sudo apt-get -qq --no-install-recommends install \
    ruby-json \
    rubygems-integration \
    socat"
  run "gem install bundler --no-rdoc --no-ri"
  run "cd modules/remotebackend"
  run "ruby -S bundle install"
  run "cd ../.."

  # tinydns
  run "sudo apt-get -qq --no-install-recommends install \
    libcdb-dev"

  # No backend
  run "sudo apt-get -qq --no-install-recommends install \
    authbind \
    faketime"
  run "sudo touch /etc/authbind/byport/53"
  run "sudo chmod 755 /etc/authbind/byport/53"
}

install_docs() {
  ### documentation requirements
  run "sudo apt-get -qq --no-install-recommends install \
    pandoc \
    xmlto"

  # documentation test requirements
  run "virtualenv $HOME/.venv"
  run "source $HOME/.venv/bin/activate"
  run "pip install -q pandocfilters==1.2.3 mkdocs==0.14 linkchecker==9.3 click==5.1"
  run "deactivate"
}

install_recursor() {
  # recursor test requirements / setup
  run "sudo apt-get -qq --no-install-recommends install \
    authbind \
    daemontools \
    libbotan-1.10-0 \
    liblua5.2-0 \
    moreutils \
    jq"
  run "cd .."
  run "wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip"
  run "unzip top-1m.csv.zip -d ./pdns/regression-tests"
  PDNS_SERVER_VERSION="0.0.880gcb54743-1pdns"
  run "wget https://downloads.powerdns.com/autobuilt/auth/deb/$PDNS_SERVER_VERSION.trusty-amd64/pdns-server_$PDNS_SERVER_VERSION.trusty_amd64.deb"
  run "wget https://downloads.powerdns.com/autobuilt/auth/deb/$PDNS_SERVER_VERSION.trusty-amd64/pdns-tools_$PDNS_SERVER_VERSION.trusty_amd64.deb"
  run "sudo dpkg -i pdns-server_$PDNS_SERVER_VERSION.trusty_amd64.deb pdns-tools_$PDNS_SERVER_VERSION.trusty_amd64.deb"
  run 'for suffix in {1..40}; do sudo /sbin/ip addr add 10.0.3.$suffix/32 dev lo; done'
  run "sudo touch /etc/authbind/byport/53"
  run "sudo chmod 755 /etc/authbind/byport/53"
  run "cd pdns"
}

install_dnsdist() {
  printf ""
}

build_auth() {
  run "./bootstrap"
  # Build without --enable-botan1.10 option, Botan/SoftHSM conflict #2496
  run "CFLAGS='-O1' CXXFLAGS='-O1' ./configure \
    --with-dynmodules='bind gmysql geoip gpgsql gsqlite3 ldap lua mydns opendbx pipe random remote tinydns' \
    --with-modules='' \
    --with-sqlite3 \
    --enable-libsodium \
    --enable-experimental-pkcs11 \
    --enable-remotebackend-zeromq \
    --enable-tools \
    --enable-unit-tests \
    --enable-backend-unit-tests \
    --disable-dependency-tracking \
    --disable-silent-rules"
  run "make -k dist"
  run "make -k -j3"
  run "make -k install DESTDIR=/tmp/pdns-install-dir"
  run "find /tmp/pdns-install-dir -ls"
}

build_recursor() {
  export PDNS_RECURSOR_DIR=$HOME/pdns_recursor
  # distribution build
  run "./build-scripts/dist-recursor"
  run "cd pdns/recursordist"
  run "tar xf pdns-recursor-*.tar.bz2"
  run "rm -f pdns-recursor-*.tar.bz2"
  run "cd pdns-recursor-*"
  run "CFLAGS='-O1' CXXFLAGS='-O1' ./configure \
    --prefix=$PDNS_RECURSOR_DIR \
    --disable-silent-rules"
  run "make -k -j3"
  run "make install"
  run "find $PDNS_RECURSOR_DIR -ls"
  run "cd ../../.."
}

build_dnsdist(){
  run "./build-scripts/dist-dnsdist"
  run "cd pdns/dnsdistdist"
  run "tar xf dnsdist*.tar.bz2"
  run "cd dnsdist-*"
  run "CFLAGS='-O1' CXXFLAGS='-O1' ./configure \
    --enable-unit-tests \
    --enable-libsodium \
    --enable-dnscrypt \
    --prefix=$HOME/dnsdist \
    --disable-silent-rules"
  run "make -k -j3"
  run "./testrunner"
  run "make install"
  run "cd ../../.."
  run "find $HOME/dnsdist -ls"
  run "rm -rf pdns/dnsdistdist/dnsdist-*/"

}

build_docs() {
  run "./bootstrap"
  run "source $HOME/.venv/bin/activate"
  run "./configure --disable-dependency-tracking --with-modules='' --with-dyn-modules=''"
  run "make -C docs"
  run "deactivate"
}

test_auth() {
  run "make -j3 check"
  run "test -f pdns/test-suite.log && cat pdns/test-suite.log || true"
  run "test -f modules/remotebackend/test-suite.log && cat modules/remotebackend/test-suite.log || true"

  #DNSName - make -k -j3 -C pdns $(grep '(EXEEXT):' pdns/Makefile | cut -f1 -d\$ | grep -E -v 'dnsdist|calidns')
  run 'make -k -j3 -C pdns $(grep "(EXEEXT):" pdns/Makefile | cut -f1 -d\$ | grep -E -v "dnspcap2protobuf|dnsdist|calidns|speedtest")'

  run "cd pdns"
  run "./pdnsutil test-algorithms"
  run "cd .."

  run "cd regression-tests"

  run "./timestamp ./start-test-stop 5300 ldap-tree"
  run "./timestamp ./start-test-stop 5300 ldap-simple"
  run "./timestamp ./start-test-stop 5300 ldap-strict"

  run "./timestamp ./start-test-stop 5300 bind-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-narrow"
  run "./timestamp ./start-test-stop 5300 bind-hybrid-nsec3"
  #ecdsa - ./timestamp ./start-test-stop 5300 bind-dnssec-pkcs11

  run "export geoipregion=oc geoipregionip=1.2.3.4"
  run "./timestamp ./start-test-stop 5300 geoip"
  run "./timestamp ./start-test-stop 5300 geoip-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 gmysql-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gmysql-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-narrow"

  run "export GODBC_SQLITE3_DSN=pdns-sqlite3-1"
  # run "./timestamp ./start-test-stop 5300 godbc_sqlite3-nsec3"

  run "./timestamp ./start-test-stop 5300 gpgsql-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 gsqlite3-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 mydns"

  run "./timestamp ./start-test-stop 5300 opendbx-sqlite3"

  run "./timestamp ./start-test-stop 5300 remotebackend-pipe"
  run "./timestamp ./start-test-stop 5300 remotebackend-pipe-dnssec"
  run "./timestamp ./start-test-stop 5300 remotebackend-unix"
  run "./timestamp ./start-test-stop 5300 remotebackend-unix-dnssec"
  run "./timestamp ./start-test-stop 5300 remotebackend-http"
  run "./timestamp ./start-test-stop 5300 remotebackend-http-dnssec"
  run "./timestamp ./start-test-stop 5300 remotebackend-zeromq"
  run "./timestamp ./start-test-stop 5300 remotebackend-zeromq-dnssec"

  run "./timestamp ./start-test-stop 5300 tinydns"
  run "cd .."

  run "cd regression-tests.rootzone"
  run "./timestamp ./start-test-stop 5300 bind-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-narrow"
  run "./timestamp ./start-test-stop 5300 bind-hybrid-nsec3"

  run "./timestamp ./start-test-stop 5300 gmysql-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gmysql-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 gpgsql-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 gsqlite3-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-narrow"

  run "cd .."

  ### api ###
  run "cd regression-tests.api"
  run "./runtests authoritative"
  run "cd .."

  ### no backend tests ###
  run "cd regression-tests.nobackend/"
  run "./runtests"
  run "test ! -s ./failed_tests"
  run "cd .."

  run "rm -f regression-tests/zones/*-slave.*" #FIXME
}

test_recursor() {
  export PDNSRECURSOR="${PDNS_RECURSOR_DIR}/sbin/pdns_recursor"
  export DNSBULKTEST="/usr/bin/dnsbulktest"
  export RECCONTROL="${PDNS_RECURSOR_DIR}/bin/rec_control"
  run "./build-scripts/test-recursor"
  export RECURSOR="${PDNSRECURSOR}"
  run "cd regression-tests"
  run "THRESHOLD=90 TRACE=no ./timestamp ./recursor-test 5300 25000"
  run "cd .."

  run "cd regression-tests.api"
  run "./runtests recursor"
  run "cd .."
}

test_docs() {
  run "source $HOME/.venv/bin/activate"
  run "make -C docs check-links"
  run " deactivate"
}

test_dnsdist(){
  run "cd regression-tests.dnsdist"
  run "DNSDISTBIN=$HOME/dnsdist/bin/dnsdist ./runtests -v"
  run "rm -f ./DNSCryptResolver.cert ./DNSCryptResolver.key"
  run "cd .."
}

test_repo(){
  run "git status"
  run "git status | grep -q clean"
}

# global build requirements
run "sudo apt-get -qq --no-install-recommends install \
  libboost-all-dev \
  liblua5.1-dev \
  libedit-dev \
  pandoc"

run "cd .."
run "wget http://ppa.launchpad.net/kalon33/gamesgiroll/ubuntu/pool/main/libs/libsodium/libsodium-dev_1.0.3-1~ppa14.04+1_amd64.deb"
run "wget http://ppa.launchpad.net/kalon33/gamesgiroll/ubuntu/pool/main/libs/libsodium/libsodium13_1.0.3-1~ppa14.04+1_amd64.deb"
run "sudo dpkg -i libsodium-dev_1.0.3-1~ppa14.04+1_amd64.deb libsodium13_1.0.3-1~ppa14.04+1_amd64.deb"
run "cd pdns"

install_$PDNS_BUILD_PRODUCT

build_$PDNS_BUILD_PRODUCT

test_$PDNS_BUILD_PRODUCT

if [ $PDNS_BUILD_PRODUCT == "auth" ]; then
  test_repo
fi
