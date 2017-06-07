#!/bin/bash -e
echo ""
echo "from:  http://dnsdist.org/download/"
echo ""
echo "clone from:  git clone https://github.com/PowerDNS/pdns.git"
echo "--or from our copy--"
echo "https://github.com/GlobalCyberAlliance/pdns.git"
echo ""

echo "cd ../pdns/dnsdistdist"
echo ""
cd ../pdns/dnsdistdist
echo ""
echo "autoreconf -i"
echo ""
autoreconf -i
echo ""
echo "NOTE: configure with libsodium enabled to allow cache test to succeed - Seth - Global Cyber Alliance"
echo "./configure --enable-libsodium"
./configure --enable-libsodium
echo ""
echo "do a \"make clean\" incase this is not the first time through"
echo ""
make clean
echo ""
echo "now do a make"
echo ""
echo "make"
echo ""
make
echo ""
echo "test out the cache code"
echo ""
cd "../../regression-tests.dnsdist"
echo ""
echo "test_Caching"
DNSDISTBIN=../pdns/dnsdistdist/dnsdist ./runtests test_Caching 
echo ""
echo "test_CacheHitResponses"
DNSDISTBIN=../pdns/dnsdistdist/dnsdist ./runtests test_CacheHitResponses
echo ""
echo "you can now do \"make install\" if desired."
echo ""
echo "finished"



