#!/bin/sh

common(){
  git describe --always --dirty=+
  wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
  unzip top-1m.csv.zip -d ./pdns/regression-tests
}

linux(){
  sudo /sbin/ip addr add 10.0.3.0/24 dev lo
  sudo /sbin/ip addr add 1.2.3.4/32 dev lo
  sudo rm -f /etc/apt/sources.list.d/travis_ci_zeromq3-source.list
  sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
  sudo add-apt-repository -y ppa:boost-latest/ppa
  sudo apt-get update -qq
  sudo apt-get -qq install g++-4.8
  sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 90
  sudo apt-get install --quiet --quiet --no-install-recommends \
    alien \
    authbind \
    bc \
    bind9utils \
    daemontools \
    dnsutils \
    faketime \
    geoip-database \
    ldnsutils \
    boost1.55 \
    libbotan1.10-dev \
    libcdb-dev \
    libcdb-dev \
    libcurl4-openssl-dev \
    libldap2-dev \
    liblua5.1-posix1 \
    libnet-dns-perl \
    libopendbx1-dev \
    libopendbx1-sqlite3 \
    libp11-kit-dev \
    libtolua-dev \
    libtool \
    links \
    moreutils \
    p11-kit \
    pkg-config \
    python-virtualenv \
    rpm \
    ruby-json \
    ruby-sqlite3 \
    ruby1.9.1 \
    rubygems \
    socat \
    softhsm \
    time \
    unbound-host \
    xmlto
  sudo sh -c 'sed s/precise/trusty/g /etc/apt/sources.list > /etc/apt/sources.list.d/trusty.list'
  sudo apt-get update --quiet --quiet
  sudo apt-get install --quiet --quiet
    liblmdb0 \
    liblmdb-dev \
    lmdb-utils \
    libgeoip-dev \
    libyaml-cpp-dev \
    libzmq3-dev \
    pandoc
  sudo pip install pandocfilters==1.2.3 mkdocs==0.14 linkchecker==9.3 click==5.1
  sudo update-alternatives --set ruby /usr/bin/ruby1.9.1
  sudo touch /etc/authbind/byport/53
  sudo chmod 755 /etc/authbind/byport/53
  cd ..
  wget ftp://ftp.nominum.com/pub/nominum/dnsperf/2.0.0.0/dnsperf-2.0.0.0-1-rhel-6-x86_64.tar.gz
  tar xzvf dnsperf-2.0.0.0-1-rhel-6-x86_64.tar.gz
  fakeroot alien --to-deb dnsperf-2.0.0.0-1/dnsperf-2.0.0.0-1.el6.x86_64.rpm
  sudo dpkg -i dnsperf_2.0.0.0-2_amd64.deb
  wget https://xs.powerdns.com/tmp/libsodium_1.0.2-1_amd64.deb
  sudo dpkg -i libsodium_1.0.2-1_amd64.deb
  cd pdns
  travis_retry gem install bundler --no-rdoc --no-ri
  cd modules/remotebackend
  travis_retry ruby -S bundle install
  cd ../..
  sudo mkdir -p /etc/pkcs11/modules/
  sudo cp -f regression-tests/softhsm.mod /etc/pkcs11/modules/softhsm
  sudo cp -f regression-tests/softhsm.conf /etc/softhsm/softhsm.conf
  sudo chmod 0755 /etc/softhsm/
  sudo chmod 0644 /etc/softhsm/softhsm.conf
  sudo chmod 0777 /var/lib/softhsm
  p11-kit -l # ensure it's ok
}

osx(){
  brew update
  brew install boost
  brew install ragel
  brew install w3m
  brew install moreutils
  brew install sqlite3
}

common
$TRAVIS_OS_NAME
