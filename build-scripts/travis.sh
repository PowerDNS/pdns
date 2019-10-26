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

  # for validns
  run "sudo add-apt-repository -y ppa:jelu/validns"
  run 'curl "http://keyserver.ubuntu.com:11371/pks/lookup?op=get&search=0x7AA4AC1F04A52E842B88094F01B7B7D6564DECD0" | sudo apt-key add - '

  # geoip-backend
  run "sudo add-apt-repository -y ppa:maxmind/ppa"
  run "gpg --keyserver keyserver.ubuntu.com --recv-keys DE742AFA"
  run "gpg --export DE742AFA | sudo apt-key add -"
  run "sudo apt-get update"
  run "sudo apt-get -qq --no-install-recommends install \
    libgeoip-dev \
    libyaml-cpp-dev \
    libmaxminddb-dev"

  # lmdb-backend
  run "sudo apt-get -qq --no-install-recommends install \
    liblmdb-dev"

  # opendbx-backend
  run "sudo apt-get -qq --no-install-recommends install \
    libopendbx1-dev \
    libopendbx1-sqlite3"

  # remote-backend build requirements
  run "sudo apt-get -qq --no-install-recommends install \
    libzmq3-dev"

  # godbc-backend
  run "sudo apt-get -qq --no-install-recommends install \
    libsqliteodbc"

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
  run "wget https://github.com/dblacka/jdnssec-tools/releases/download/0.14/jdnssec-tools-0.14.tar.gz"
  run "sudo tar xfz jdnssec-tools-0.14.tar.gz --strip-components=1 -C /"
  run "cd ${TRAVIS_BUILD_DIR}"

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
    alien\
    fakeroot"
  run "cd .."
  run "wget https://downloads.powerdns.com/tmp/dnsperf-2.0.0.0-1-rhel-6-x86_64.tar.gz"
  run "tar xzvf dnsperf-2.0.0.0-1-rhel-6-x86_64.tar.gz"
  run "fakeroot alien --to-deb dnsperf-2.0.0.0-1/dnsperf-2.0.0.0-1.el6.x86_64.rpm"
  run "sudo dpkg -i dnsperf_2.0.0.0-2_amd64.deb"
  run "cd ${TRAVIS_BUILD_DIR}"

  # geoip-backend test requirements / setup
  run "sudo apt-get -qq --no-install-recommends install \
    geoip-database"

  # gmysql-backend test requirements
  # as of 2016/12/01, mysql-5.6 is now installed in the default travis image
  # see https://github.com/travis-ci/travis-ci/issues/6961
  #run "sudo apt-get -qq --no-install-recommends install \
  #  mysql-server"

  # godbc-backend test setup
  run 'echo -e "[pdns-sqlite3-1]\nDriver = SQLite3\nDatabase = ${PWD}/regression-tests/pdns.sqlite3\n\n[pdns-sqlite3-2]\nDriver = SQLite3\nDatabase = ${PWD}/regression-tests/pdns.sqlite32\n" > ${HOME}/.odbc.ini'
  run 'echo ${HOME}/.odbc.ini'
  run 'cat ${HOME}/.odbc.ini'

  # remote-backend tests requirements
  run "sudo apt-get -qq --no-install-recommends install \
    ruby-json \
    rubygems-integration \
    socat"
  run "gem update --system"
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

  # Install dnsmasq to make lookups more robust
  run "sudo apt-get -qq --no-install-recommends install \
    dnsmasq"
  run 'echo listen-address=127.0.0.53 | sudo tee /etc/dnsmasq.d/local.conf'
  run 'echo bind-interfaces | sudo tee -a /etc/dnsmasq.d/local.conf'

  ## WARNING
  ## after this dnsmasq restart, DNS lookups will fail for a few seconds.
  run 'sudo service dnsmasq restart'
  run "sudo resolvconf --disable-updates"
  run 'echo nameserver 127.0.0.53 | sudo tee /etc/resolv.conf'
  run "export RESOLVERIP=127.0.0.53"
}

install_ixfrdist() {
  run "sudo apt-get -qq --no-install-recommends install \
    libyaml-cpp-dev"
}

install_recursor() {
  # recursor test requirements / setup
  # lua-posix is required for the ghost tests
  # (used by the prequery script in the auth)
  run "sudo apt-get -qq --no-install-recommends install \
    authbind \
    daemontools \
    jq \
    libfaketime \
    libsnmp-dev \
    lua-posix \
    lua-socket \
    moreutils \
    snmpd"
  run "cd .."
  run "wget http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
  run "unzip top-1m.csv.zip -d ${TRAVIS_BUILD_DIR}/regression-tests"
  run 'echo -e "deb [arch=amd64] http://repo.powerdns.com/ubuntu trusty-auth-master main" | sudo tee /etc/apt/sources.list.d/pdns.list'
  run 'echo -e "Package: pdns-*\nPin: origin repo.powerdns.com\nPin-Priority: 9001" | sudo tee /etc/apt/preferences.d/pdns'
  run 'curl https://repo.powerdns.com/CBC8B383-pub.asc | sudo apt-key add - '
  run 'sudo apt-get update'
  run 'sudo apt-get -y install pdns-server pdns-tools'
  run "sudo service pdns stop"
  run 'for suffix in {1..40}; do sudo /sbin/ip addr add 10.0.3.$suffix/32 dev lo; done'
  run "sudo touch /etc/authbind/byport/53"
  run "sudo chmod 755 /etc/authbind/byport/53"
  run "cd ${TRAVIS_BUILD_DIR}"
  # install SNMP
  run "sudo sed -i \"s/agentxperms 0700 0755 recursor/agentxperms 0700 0755 ${USER}/g\" regression-tests.recursor-dnssec/snmpd.conf"
  run "sudo cp -f regression-tests.recursor-dnssec/snmpd.conf /etc/snmp/snmpd.conf"
  run "sudo service snmpd restart"
  ## fun story, the directory perms are only applied if it doesn't exist yet, and it is created by the init script, so..
  run "sudo chmod 0755 /var/agentx"
}

install_dnsdist() {
  # test requirements / setup
  run "sudo add-apt-repository -y ppa:zeha/libfstrm-ppa"
  run 'curl "http://keyserver.ubuntu.com:11371/pks/lookup?op=get&search=0x396160EF8126A2E2" | sudo apt-key add - '
  run "sudo apt-get -qq update"
  run "sudo apt-get -qq --no-install-recommends install \
    snmpd \
    libcdb-dev \
    libfstrm-dev \
    liblmdb-dev \
    libsnmp-dev"
  run "sudo sed -i \"s/agentxperms 0700 0755 dnsdist/agentxperms 0700 0755 ${USER}/g\" regression-tests.dnsdist/snmpd.conf"
  run "sudo cp -f regression-tests.dnsdist/snmpd.conf /etc/snmp/snmpd.conf"
  run "sudo service snmpd restart"
  # fun story, the directory perms are only applied if it doesn't exist yet, and it is created by the init script, so..
  run "sudo chmod 0755 /var/agentx"
}

check_for_dangling_symlinks() {
  run '! find -L . -name missing-sources -prune -o ! -name pubsuffix.cc -type l | grep .'
}

build_auth() {
  run "autoreconf -vi"
  run "./configure \
    ${sanitizerflags} \
    --with-dynmodules='bind gmysql geoip gpgsql gsqlite3 lmdb lua opendbx pipe random remote tinydns godbc lua2' \
    --with-modules='' \
    --with-sqlite3 \
    --with-libsodium \
    --enable-experimental-pkcs11 \
    --enable-remotebackend-zeromq \
    --enable-tools \
    --enable-unit-tests \
    --enable-backend-unit-tests \
    --enable-fuzz-targets \
    --disable-dependency-tracking \
    --disable-silent-rules \
    --with-lmdb=/usr"
  run "make -k dist"
  run "make -k -j3"
  run "make -k install DESTDIR=/tmp/pdns-install-dir"
  run "find /tmp/pdns-install-dir -ls"
}

build_ixfrdist() {
  run "autoreconf -vi"
  run "./configure \
    ${sanitizerflags} \
    --with-dynmodules='bind' \
    --with-modules='' \
    --enable-ixfrdist \
    --enable-unit-tests \
    --disable-dependency-tracking \
    --disable-silent-rules"
  run "make -C ext -k -j3"
  run "cd pdns"
  run "make -k -j3 ixfrdist"
  run "cd .."
}

build_recursor() {
  export PDNS_RECURSOR_DIR=$HOME/pdns_recursor
  run "cd pdns/recursordist"
  check_for_dangling_symlinks
  run "cd ../.."
  # distribution build
  run "./build-scripts/dist-recursor"
  run "cd pdns/recursordist"
  run "tar xf pdns-recursor-*.tar.bz2"
  run "rm -f pdns-recursor-*.tar.bz2"
  run "cd pdns-recursor-*"
  run "./configure \
    ${sanitizerflags} \
    --prefix=$PDNS_RECURSOR_DIR \
    --with-libsodium \
    --enable-unit-tests \
    --enable-nod \
    --disable-dnstap \
    --disable-silent-rules"
  run "make -k -j3"
  run "make install"
  run "find $PDNS_RECURSOR_DIR -ls"
  run "cd ../../.."
}

build_dnsdist(){
  run "cd pdns/dnsdistdist"
  check_for_dangling_symlinks
  run "cd ../.."
  run "./build-scripts/dist-dnsdist"
  run "cd pdns/dnsdistdist"
  run "tar xf dnsdist*.tar.bz2"
  run "cd dnsdist-*"
  run "./configure \
    ${sanitizerflags} \
    --enable-unit-tests \
    --with-libsodium \
    --enable-dnscrypt \
    --enable-dns-over-tls \
    --enable-dnstap \
    --with-lmdb=/usr \
    --prefix=$HOME/dnsdist \
    --disable-silent-rules"
  run "make -k -j3"
  run "./testrunner"
  run "make install"
  run "cd ../../.."
  run "find $HOME/dnsdist -ls"
  run "rm -rf pdns/dnsdistdist/dnsdist-*/"

}

test_auth() {
  run "make -j3 check || (cat pdns/test-suite.log; false)"
  run "test -f pdns/test-suite.log && cat pdns/test-suite.log || true"
  run "test -f modules/remotebackend/test-suite.log && cat modules/remotebackend/test-suite.log || true"

  #DNSName - make -k -j3 -C pdns $(grep '(EXEEXT):' pdns/Makefile | cut -f1 -d\$ | grep -E -v 'dnsdist|calidns')
  run 'make -k -j3 -C pdns $(grep "(EXEEXT):" pdns/Makefile | cut -f1 -d\$)'

  run "cd pdns"
  run "./pdnsutil test-algorithms"
  run "cd .."

  run "cd regression-tests"

  #travis unbound is too old for this test (unbound 1.6.0 required)
  run "touch tests/ent-asterisk/fail.nsec"

  run "./timestamp ./start-test-stop 5300 lua-minimal nowait 0 apex-level-a-but-no-a"

  run "./timestamp ./start-test-stop 5300 bind-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-narrow"
  run "./timestamp ./start-test-stop 5300 bind-hybrid-nsec3"
  #ecdsa - ./timestamp ./start-test-stop 5300 bind-dnssec-pkcs11

  run "./timestamp ./start-test-stop 5300 geoip"
  run "./timestamp ./start-test-stop 5300 geoip-nsec3-narrow"
  run "export geoipdatabase=../modules/geoipbackend/regression-tests/GeoLiteCity.mmdb"
  run "./timestamp ./start-test-stop 5300 geoip"

  run "./timestamp ./start-test-stop 5300 gmysql-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gmysql-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 gmysql-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-narrow"

  run "export GODBC_SQLITE3_DSN=pdns-sqlite3-1"
  run "./timestamp ./start-test-stop 5300 godbc_sqlite3-nsec3"

  run "./timestamp ./start-test-stop 5300 gpgsql-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-both"
  #run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-optout-both"
  #run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 gsqlite3-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 opendbx-sqlite3"

  run "./timestamp ./start-test-stop 5300 remotebackend-pipe"
  run "./timestamp ./start-test-stop 5300 remotebackend-pipe-dnssec"
  #run "./timestamp ./start-test-stop 5300 remotebackend-unix"
  run "./timestamp ./start-test-stop 5300 remotebackend-unix-dnssec"
  #run "./timestamp ./start-test-stop 5300 remotebackend-http"
  run "./timestamp ./start-test-stop 5300 remotebackend-http-dnssec"
  #run "./timestamp ./start-test-stop 5300 remotebackend-zeromq"
  run "./timestamp ./start-test-stop 5300 remotebackend-zeromq-dnssec"

  run "./timestamp ./start-test-stop 5300 tinydns"

  run "./timestamp ./start-test-stop 5300 lmdb-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 lmdb-both"
  run "./timestamp ./start-test-stop 5300 lmdb-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 lmdb-nsec3-optout-both"

  run "rm tests/ent-asterisk/fail.nsec"

  run "cd ../modules/luabackend/test2"
  run "../../../regression-tests/timestamp ./runtest"

  run "cd ../../.."

  run "cd regression-tests.rootzone"
  run "./timestamp ./start-test-stop 5300 bind-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 bind-dnssec-nsec3-narrow"
  run "./timestamp ./start-test-stop 5300 bind-hybrid-nsec3"

  run "./timestamp ./start-test-stop 5300 gmysql-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gmysql-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 gmysql-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gmysql-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 gpgsql-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gpgsql-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 gsqlite3-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-optout-both"
  run "./timestamp ./start-test-stop 5300 gsqlite3-nsec3-narrow"

  run "./timestamp ./start-test-stop 5300 lua2"
  run "./timestamp ./start-test-stop 5300 lua2-dnssec"

  run "./timestamp ./start-test-stop 5300 lmdb-both"
  run "./timestamp ./start-test-stop 5300 lmdb-nodnssec-both"
  run "./timestamp ./start-test-stop 5300 lmdb-nsec3-both"
  # run "./timestamp ./start-test-stop 5300 lmdb-nsec3-optout-both"

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

  ### Lua rec tests ###
  run "cd regression-tests.auth-py"
  run "./runtests -v || (cat ./configs/auth/pdns.log; false)"
  run "cd .."

  run "rm -f regression-tests/zones/*-slave.*" #FIXME
}

test_ixfrdist(){
  run "cd regression-tests.ixfrdist"
  run "IXFRDISTBIN=${TRAVIS_BUILD_DIR}/pdns/ixfrdist ./runtests -v || (cat ixfrdist.log; false)"
  run "cd .."
}

test_recursor() {
  export PDNSRECURSOR="${PDNS_RECURSOR_DIR}/sbin/pdns_recursor"
  export DNSBULKTEST="/usr/bin/dnsbulktest"
  export RECCONTROL="${PDNS_RECURSOR_DIR}/bin/rec_control"
  run "cd pdns/recursordist/pdns-recursor-*"
  run "make -j 3 check || (cat test-suite.log; false)"
  run "cd ${TRAVIS_BUILD_DIR}"
  run "./build-scripts/test-recursor"
  export RECURSOR="${PDNSRECURSOR}"
  run "cd regression-tests"
  run "THRESHOLD=50 TRACE=no ./timestamp ./recursor-test 5300 50000"
  run "cd .."

  run "cd regression-tests.api"
  run "./runtests recursor"
  run "cd .."
}

test_dnsdist(){
  run "cd regression-tests.dnsdist"
  run "DNSDISTBIN=$HOME/dnsdist/bin/dnsdist ./runtests -v --ignore-files='(?:^\.|^_,|^setup\.py$|^test_DOH\.py$|^test_OCSP\.py$|^test_Prometheus\.py$|^test_TLSSessionResumption\.py$)'"
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
  libluajit-5.1-dev \
  libedit-dev \
  libprotobuf-dev \
  protobuf-compiler"

run "cd .."
run "wget http://ppa.launchpad.net/kalon33/gamesgiroll/ubuntu/pool/main/libs/libsodium/libsodium-dev_1.0.3-1~ppa14.04+1_amd64.deb"
run "wget http://ppa.launchpad.net/kalon33/gamesgiroll/ubuntu/pool/main/libs/libsodium/libsodium13_1.0.3-1~ppa14.04+1_amd64.deb"
run "sudo dpkg -i libsodium-dev_1.0.3-1~ppa14.04+1_amd64.deb libsodium13_1.0.3-1~ppa14.04+1_amd64.deb"
run "cd ${TRAVIS_BUILD_DIR}"

compilerflags="-O1 -Werror=vla"
sanitizerflags=""
if [ "$CC" = "clang" ]
then
  compilerflags="$compilerflags -Werror=string-plus-int"
  if [ "${PDNS_BUILD_PRODUCT}" = "recursor" ]; then
    sanitizerflags="${sanitizerflags} --enable-asan"
  elif [ "${PDNS_BUILD_PRODUCT}" = "dnsdist" ]; then
    sanitizerflags="${sanitizerflags} --enable-asan --enable-ubsan"
  elif [ "${PDNS_BUILD_PRODUCT}" = "ixfrdist" ]; then
    sanitizerflags="${sanitizerflags} --enable-asan --enable-ubsan"
  fi
fi
export CFLAGS=$compilerflags
export CXXFLAGS=$compilerflags
export sanitizerflags
# We need a suppression for UndefinedBehaviorSanitizer with ixfrdist,
# because of a vptr bug fixed in Boost 1.57.0:
# https://github.com/boostorg/any/commit/c92ab03ab35775b6aab30f6cdc3d95b7dd8fc5c6
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:suppressions=${TRAVIS_BUILD_DIR}/build-scripts/UBSan.supp"

install_$PDNS_BUILD_PRODUCT

build_$PDNS_BUILD_PRODUCT

test_$PDNS_BUILD_PRODUCT

if [ $PDNS_BUILD_PRODUCT == "auth" ]; then
  test_repo
fi
