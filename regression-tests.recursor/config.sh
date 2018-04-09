#!/bin/bash
set -e
if [ "${PDNS_DEBUG}" = "YES" ]; then
  set -x
fi

export PDNS=${PDNS:-${PWD}/../pdns/pdns_server}
export PDNSRECURSOR=${PDNSRECURSOR:-${PWD}/../pdns/recursordist/pdns_recursor}
export RECCONTROL=${RECCONTROL:-${PWD}/../pdns/recursordist/rec_control}

. ./vars

if [ -z "$PREFIX" ]
then
    echo "config not found or PREFIX not set"
    exit 1
fi

if [ -z "$AUTHRUN" ]
then
    echo "config not found or AUTHRUN not set"
    exit 1
fi

rm -rf configs/
mkdir configs

cat > run-auth <<EOF
#!/bin/sh
$AUTHRUN
EOF
chmod +x run-auth

if [ \! -x "$PDNSRECURSOR" ]
then
  echo "Could not find an executable pdns_recursor at \"$PDNSRECURSOR\", check PDNSRECURSOR"
  echo "Continuing with configuration anyhow"
fi

if [ \! -x "$PDNS" ]
then
  echo "Could not find an executable pdns_server at \"$PDNS\", check PDNS"
  echo "Continuing with configuration anyhow"
fi

cd configs

for dir in recursor-service recursor-service2 recursor-service3 recursor-service4; do
  mkdir -p /tmp/$dir
  mkdir -p $dir
  cd $dir

  cat > run <<EOF
#!/bin/sh
$RECRUN
EOF
  chmod +x run

  cat > hintfile << EOF
.                        3600 IN NS  ns.root.
ns.root.                 3600 IN A   $PREFIX.8
EOF

  cd ..
done

SOA="ns.example.net. hostmaster.example.net. 1 3600 1800 1209600 300"

### fake root zone
mkdir $PREFIX.8
cat > $PREFIX.8/ROOT.zone <<EOF
.                        3600 IN SOA $SOA
.                        3600 IN NS  ns.root.
ns.root.                 3600 IN A   $PREFIX.8
net.                     3600 IN NS  ns.example.net.
net.                     3600 IN NS  ns2.example.net.
ns.example.net.          3600 IN A   $PREFIX.10
ns2.example.net.         3600 IN A   $PREFIX.11
EOF

### plain example.net zone
mkdir $PREFIX.10
cat > $PREFIX.10/example.net.zone <<EOF
example.net.             3600 IN SOA $SOA
example.net.             3600 IN NS  ns.example.net.
example.net.             3600 IN NS  ns2.example.net.
ns.example.net.          3600 IN A   $PREFIX.10
ns2.example.net.         3600 IN A   $PREFIX.11
www.example.net.         3600 IN A   192.0.2.1
www2.example.net.        3600 IN A   192.0.2.2
www3.example.net.        3600 IN A   192.0.2.3
www4.example.net.        3600 IN A   192.0.2.4
www5.example.net.        3600 IN A   192.0.2.5
default.example.net.     3600 IN A   192.0.2.42
weirdtxt.example.net.    3600 IN IN  TXT "x\014x"
arthur.example.net.      3600 IN NS  ns.arthur.example.net.
arthur.example.net.      3600 IN NS  ns2.arthur.example.net.
ns.arthur.example.net.   3600 IN A   $PREFIX.12
ns2.arthur.example.net.  3600 IN A   $PREFIX.13
prefect.example.net.     3600 IN NS  ns.prefect.example.net.
ns.prefect.example.net.  3600 IN A   $PREFIX.14
marvin.example.net.      3600 IN NS  ns.marvin.example.net.
ns.marvin.example.net.   3600 IN A   $PREFIX.15
trillian.example.net.    3600 IN NS  ns.trillian.example.net.
ns.trillian.example.net. 3600 IN A   $PREFIX.16
ghost.example.net.       3600 IN NS  ns.ghost.example.net.
ns.ghost.example.net.    3600 IN A   $PREFIX.17
ford.example.net.        3600 IN NS  ns.ford.example.net.
ns.ford.example.net.     3600 IN A   $PREFIX.12
hijackme.example.net.    3600 IN NS  ns.hijackme.example.net.
ns.hijackme.example.net. 3600 IN A   $PREFIX.20
hijacker.example.net.    3600 IN NS  ns.hijacker.example.net.
ns.hijacker.example.net. 3600 IN A   $PREFIX.21
answer-cname-in-local.example.net. 3600 IN NS ns.answer-cname-in-local.example.net.
pfsbox.answer-cname-in-local.example.net. 3600 IN NS ns.answer-cname-in-local.example.net.
box.answer-cname-in-local.example.net. 3600 IN NS ns.answer-cname-in-local.example.net.
ns.answer-cname-in-local.example.net. 3600 IN A  $PREFIX.22
not-auth-zone.example.net. 3600 IN NS ns.not-auth-zone.example.net.
ns.not-auth-zone.example.net. 3600 IN A $PREFIX.23
lowercase-outgoing.example.net. 3600 IN NS ns.lowercase-outgoing.example.net.
ns.lowercase-outgoing.example.net. 3600 IN A $PREFIX.24
nxdomainme.example.net.            3600 IN A $PREFIX.25
EOF

mkdir $PREFIX.11
cp $PREFIX.10/example.net.zone $PREFIX.11/

### plain delegated zone, no surprises
### also serves as intentionally NON-authoritative for ford
mkdir $PREFIX.12
cat > $PREFIX.12/arthur.example.net.zone <<EOF
arthur.example.net.      3600 IN SOA $SOA
arthur.example.net.      3600 IN NS  ns.arthur.example.net.
arthur.example.net.      3600 IN NS  ns2.arthur.example.net.
arthur.example.net.      3600 IN MX  mail.arthur.example.net.
ns.arthur.example.net.   3600 IN A   $PREFIX.12
ns2.arthur.example.net.  3600 IN A   $PREFIX.13
www.arthur.example.net.  3600 IN A   192.0.2.2
www2.arthur.example.net. 3600 IN A   192.0.2.6
mail.arthur.example.net. 3600 IN A   192.0.2.3
big.arthur.example.net.  3600 IN TXT "the quick brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "The quick brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THe quick brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE quick brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE quick brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE Quick brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUick brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUIck brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICk brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK Brown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BRown fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROwn fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWn fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN Fox jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOx jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX Jumps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUmps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMps over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPs over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS Over the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVer the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVEr the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER the lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER The lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THe lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE Lazy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE LAzy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE LAZy dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE LAZY dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE LAZY dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE LAZY Dog"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOg"
big.arthur.example.net.  3600 IN TXT "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
srv.arthur.example.net.  3600 IN SRV 0 100 389 server2.example.net.
rp.arthur.example.net.   3600 IN RP  ahu.ds9a.nl. counter
type1234.arthur.example.net. 3600 IN TYPE1234 \# 2 4142
EOF

mkdir $PREFIX.13
cp $PREFIX.12/arthur.example.net.zone $PREFIX.13

### zone with various CNAMEs, valid packets
mkdir $PREFIX.14
cat > $PREFIX.14/prefect.example.net.zone <<EOF
prefect.example.net.           3600 IN SOA   $SOA
prefect.example.net.           3600 IN NS    ns.prefect.example.net.
ns.prefect.example.net.        3600 IN A     $PREFIX.14
www-a.prefect.example.net.     3600 IN CNAME www-a-2.prefect.example.net.
;www-a-2.prefect.example.net.  NXDOMAIN
www-b.prefect.example.net.     3600 IN CNAME www-b-2.prefect.example.net.
www-b-2.prefect.example.net.   3600 IN A     192.0.2.4
www-c.prefect.example.net.     3600 IN CNAME www-b-2.prefect.example.net.
;www-c-2.prefect.example.net.  NOERROR on A
www-c-2.prefect.example.net.   3600 IN AAAA  2001:db8::1
www-d.prefect.example.net.     3600 IN CNAME www.arthur.example.net.
EOF

### zone with valid in-zone CNAME, invalid NXDOMAIN in response
mkdir $PREFIX.15
cat > $PREFIX.15/marvin.example.net.zone <<EOF
marvin.example.net.          3600    IN  SOA $SOA
marvin.example.net.          3600    IN  NS  ns.marvin.example.net.
ns.marvin.example.net.   3600 IN A   $PREFIX.15
www.marvin.example.net.      3600    IN  CNAME   android.marvin.example.net.
android.marvin.example.net.  3600    IN  A   192.0.2.5
EOF

cat > $PREFIX.15/prequery.lua <<EOF
if not newDN then
  function newDN(x)
    return x
  end
end
function prequery ( dnspacket )
    qname, qtype = dnspacket:getQuestion()
    if qtype == pdns.A and qname == "www.marvin.example.net."
    then
        dnspacket:setRcode(pdns.NXDOMAIN)
        ret = {}
        ret[1] = newDR(newDN(qname), "CNAME", 3600, "android.marvin.example.net", 1)
        ret[2] = newDR(newDN("marvin.example.net"), "SOA", 3600, "$SOA", 2)
        dnspacket:addRecords(ret)
        return true
    end
    return false
end
EOF

### zone with working cross-zone CNAME, invalid NXDOMAIN in response
mkdir $PREFIX.16
cat > $PREFIX.16/trillian.example.net.zone <<EOF
trillian.example.net.         3600 IN SOA $SOA
trillian.example.net.         3600 IN NS  ns.trillian.example.net.
ns.trillian.example.net.      3600 IN A     $PREFIX.16
www.trillian.example.net.     3600 IN CNAME www2.arthur.example.net.
EOF

cat > $PREFIX.16/prequery.lua <<EOF
if not newDN then
  function newDN(x)
    return x
  end
end
function prequery ( dnspacket )
    qname, qtype = dnspacket:getQuestion()
    if qtype == pdns.A and qname == "www.trillian.example.net."
    then
        dnspacket:setRcode(pdns.NXDOMAIN)
        ret = {}
        ret[1] = newDR(newDN(qname), "CNAME", 3600, "www2.arthur.example.net", 1)
        ret[2] = newDR(newDN(""), "SOA", 3600, "$SOA", 2)
        dnspacket:addRecords(ret)
        return true
    end
    return false
end
EOF

### parent zone for ghost testing
mkdir $PREFIX.17
cat > $PREFIX.17/ghost.example.net.zone <<EOF
ghost.example.net.      3600 IN SOA $SOA
ghost.example.net.      3600 IN NS  ns.ghost.example.net.
ns.ghost.example.net.   3600 IN A   $PREFIX.17
1.ghost.example.net.      10 IN NS  ns.1.ghost.example.net.
ns.1.ghost.example.net.   10 IN A   $PREFIX.18
2.ghost.example.net.      10 IN NS  ns.2.ghost.example.net.
ns.2.ghost.example.net.   10 IN A   $PREFIX.19
EOF

cat > $PREFIX.17/prequery.lua <<EOF
posix = require 'posix'

if not newDN then
  function newDN(x)
    return x
  end
end
function prequery ( dnspacket )
    qname, qtype = dnspacket:getQuestion()
    if (string.sub(tostring(qname), -21) == ".1.ghost.example.net." and posix.stat('drop-1')) or
       (string.sub(tostring(qname), -21) == ".2.ghost.example.net." and posix.stat('drop-2'))
    then
        dnspacket:setRcode(pdns.NXDOMAIN)
        ret = {}
        ret[1] = newDR(newDN("ghost.example.net"), "SOA", 3600, "$SOA", 2)
        dnspacket:addRecords(ret)
        return true
    end
    return false
end
EOF

### ghost domain with ever-changing NSset
mkdir $PREFIX.18
cat > $PREFIX.18/1.ghost.example.net.zone <<EOF
1.ghost.example.net.    3600 IN SOA $SOA
1.ghost.example.net.      20 IN NS  ns.1.ghost.example.net.
ns.1.ghost.example.net.   20 IN A   $PREFIX.18
*.www.1.ghost.example.net.  20 IN A   192.0.2.7
EOF

cat > $PREFIX.18/prequery.lua <<EOF
i=0

if not newDN then
  function newDN(x)
    return x
  end
end
function prequery ( dnspacket )
    i = i + 1
    qname, qtype = dnspacket:getQuestion()
    if qtype == pdns.A and string.sub(tostring(qname), -25) == ".www.1.ghost.example.net."
    then
        dnspacket:setRcode(pdns.NOERROR)
        ret = {}
        -- www.1.ghost.example.net. 20  IN  A   192.0.2.7
        ret[1] = newDR(newDN(qname), "A", 20, "192.0.2.7", 1)
        -- 1.ghost.example.net. 20  IN  NS  ns.1.ghost.example.net.
        ret[2] = newDR(newDN("1.ghost.example.net"), "NS", 20, "ns"..i..".1.ghost.example.net", 2)
        -- ns.1.ghost.example.net.  20  IN  A   $PREFIX.18
        ret[3] = newDR(newDN("ns"..i..".1.ghost.example.net"), "A", 20, "$PREFIX.18", 3)
        dnspacket:addRecords(ret)
        return true
    end
    return false
end
EOF

### ghost domain with static NSset
mkdir $PREFIX.19
cat > $PREFIX.19/2.ghost.example.net.zone <<EOF
2.ghost.example.net.    3600 IN SOA $SOA
2.ghost.example.net.      20 IN NS  ns.2.ghost.example.net.
ns.2.ghost.example.net.   20 IN A   $PREFIX.19
*.www.2.ghost.example.net.  20 IN A   192.0.2.8
EOF
cat > $PREFIX.19/prequery.lua <<EOF
if not newDN then
  function newDN(x)
    return x
  end
end
function prequery ( dnspacket )
    qname, qtype = dnspacket:getQuestion()
    if qtype == pdns.A and string.sub(tostring(qname), -25) == ".www.2.ghost.example.net."
    then
        dnspacket:setRcode(pdns.NOERROR)
        ret = {}
        ret[1] = newDR(newDN(qname), "A", 20, "192.0.2.8", 1)
        ret[2] = newDR(newDN("2.ghost.example.net"), "NS", 20, "ns.2.ghost.example.net", 2)
        ret[3] = newDR(newDN("ns.2.ghost.example.net"), "A", 20, "$PREFIX.19", 3)
        dnspacket:addRecords(ret)
        return true
    end
    return false
end
EOF

### plain domain as target for hijacking
mkdir $PREFIX.20
cat > $PREFIX.20/hijackme.example.net.zone <<EOF
hijackme.example.net.    3600 IN SOA $SOA
hijackme.example.net.      20 IN NS  ns.hijackme.example.net.
ns.hijackme.example.net.   20 IN A   $PREFIX.20
www.hijackme.example.net.  20 IN A   192.0.2.20
EOF

### domain designed to hijack the A of ns.hijackme.example.net
mkdir $PREFIX.21
cat > $PREFIX.21/hijacker.example.net.zone <<EOF
hijacker.example.net.    3600 IN SOA $SOA
hijacker.example.net.      20 IN NS  ns.hijackme.example.net.
;ns.hijackme.example.net.   20 IN A   $PREFIX.21

EOF

cat > $PREFIX.21/hijackme.example.net.zone <<EOF
hijackme.example.net.    3600 IN SOA $SOA
hijackme.example.net.      20 IN NS  ns.hijackme.example.net.
ns.hijackme.example.net.   20 IN A   $PREFIX.21
www.hijackme.example.net.  20 IN A   192.0.2.21

EOF

## Several domains where one gets overwritten as a local auth zone
mkdir $PREFIX.22
cat > $PREFIX.22/box.answer-cname-in-local.example.net.zone <<EOF
box.answer-cname-in-local.example.net. 3600 IN SOA $SOA
box.answer-cname-in-local.example.net. 20 IN NS ns.answer-cname-in-local.example.net.

global.box.answer-cname-in-local.example.net. 20 IN NS ns.answer-cname-in-local.example.net.
service.box.answer-cname-in-local.example.net. 20 IN CNAME pfs.global.box.answer-cname-in-local.example.net.

EOF

cat > $PREFIX.22/global.box.answer-cname-in-local.example.net.zone <<EOF
global.box.answer-cname-in-local.example.net. 3600 IN SOA $SOA
global.box.answer-cname-in-local.example.net. 20 IN NS ns.answer-cname-in-local.example.net.

pfs.global.box.answer-cname-in-local.example.net. 20 IN  CNAME vip-metropole.pfsbox.answer-cname-in-local.example.net.

EOF

cat > $PREFIX.22/pfsbox.answer-cname-in-local.example.net.zone <<EOF
pfsbox.answer-cname-in-local.example.net. 3600 IN SOA $SOA
pfsbox.answer-cname-in-local.example.net. 20 IN NS ns.answer-cname-in-local.example.net.

vip-metropole.pfsbox.answer-cname-in-local.example.net. 20 IN  A 10.0.0.1
vip-reunion.pfsbox.answer-cname-in-local.example.net. 20 IN  A 10.1.1.1

EOF

# Used for the auth-zones test, to test a CNAME inside an auth-zone to a name
# outside of and auth-zone
mkdir $PREFIX.23
cat > $PREFIX.23/not-auth-zone.example.net.zone <<EOF
not-auth-zone.example.net. 3600 IN SOA $SOA
not-auth-zone.example.net. 20 IN NS ns.not-auth-zone.example.net.

ns.not-auth-zone.example.net. 20 IN  A $PREFIX.23
host1.not-auth-zone.example.net. 20 IN  A 127.0.0.57
EOF

cat > $PREFIX.23/france.auth-zone.example.net.zone <<EOF
france.auth-zone.example.net. 3600 IN SOA $SOA
france.auth-zone.example.net. 3600 IN NS ns1.auth-zone.example.net
www.france.auth-zone.example.net. 3600 IN A 192.0.2.23
france.auth-zone.example.net. 3600 IN A 192.0.2.223
EOF

# And for the recursor
cat > recursor-service/global.box.answer-cname-in-local.example.net.zone <<EOF
global.box.answer-cname-in-local.example.net. 3600 IN SOA $SOA
global.box.answer-cname-in-local.example.net. 20 IN NS ns.answer-cname-in-local.example.net.

pfs.global.box.answer-cname-in-local.example.net. 20 IN  CNAME vip-reunion.pfsbox.answer-cname-in-local.example.net.

EOF

# For the auth-zones test
cat > recursor-service/auth-zone.example.net.zone <<EOF
auth-zone.example.net. 3600 IN SOA $SOA
auth-zone.example.net. 20 IN NS localhost.example.net.

host1.auth-zone.example.net. 20 IN A 127.0.0.55
host1.auth-zone.example.net. 20 IN AAAA 2001:DB8::1:45BA

host2.auth-zone.example.net. 20 IN CNAME host1.another-auth-zone.example.net.

host3.auth-zone.example.net. 20 IN CNAME host1.not-auth-zone.example.net.
*.wild.auth-zone.example.net.	3600 IN	TXT "Hi there!"
france.auth-zone.example.net.	20	IN NS 	ns1.auth-zone.example.net.
ns1.auth-zone.example.net. 	20	IN	A	$PREFIX.23
*.something.auth-zone.example.net.      20      IN      CNAME   host1.auth-zone.example.net.
EOF

mkdir $PREFIX.24
cat > $PREFIX.24/lowercase-outgoing.example.net.zone <<EOF
lowercase-outgoing.example.net. 3600 IN SOA $SOA
lowercase-outgoing.example.net. 20 IN NS ns.lowercase-outgoing.example.net.

ns.lowercase-outgoing.example.net. 20 IN  A $PREFIX.24
host.lowercase-outgoing.example.net. 20 IN  A 127.0.0.57
EOF

cat > $PREFIX.24/prequery.lua <<EOF
filename = "questions.txt"

--- Truncate file
file = io.open(filename, "w")
file:close()

if not newDN then
  function newDN(x)
    return x
  end
end
function prequery ( dnspacket )
    qname, qtype = dnspacket:getQuestion()
    file = io.open('questions.txt', "a")
    file:write(tostring(qname) .. "\n")
    file:close()

    return false
end
EOF

cat > recursor-service/another-auth-zone.example.net.zone <<EOF
another-auth-zone.example.net. 3600 IN SOA $SOA
another-auth-zone.example.net. 20 IN NS localhost.example.net.

host1.another-auth-zone.example.net. 20 IN A 127.0.0.56
EOF

for dir in $PREFIX.*
do
    cat > $dir/pdns.conf <<EOF
module-dir=../../../regression-tests/modules
launch=bind
daemon=no
local-address=$dir
local-ipv6=
bind-config=named.conf
no-shuffle
socket-dir=.
cache-ttl=0
negquery-cache-ttl=0
query-cache-ttl=0
distributor-threads=1

EOF

    if [ -e $dir/prequery.lua ]
    then
        echo 'lua-prequery-script=prequery.lua' >> $dir/pdns.conf
    fi

    cat > $dir/named.conf <<EOF
options {
    directory "./";
};
EOF
    for zone in $(ls $dir | grep '\.zone$' | sed 's/\.zone$//')
    do
        realzone=$zone
        if [ $realzone = ROOT ]
        then
            realzone='.'
        fi
        cat >> $dir/named.conf <<EOF
zone "$realzone"{
    type master;
    file "./$zone.zone";
};
EOF
    done
    ln -s ../../run-auth $dir/run
done

cat > recursor-service/forward-zones-file << EOF
# Some comment that should be ignored
forward-zones-test.non-existing.powerdns.com=8.8.8.8
forward-zones-test2.non-existing.powerdns.com=8.8.8.8# This comment should be ignored as well
EOF

cat > recursor-service/recursor.conf <<EOF
webserver=yes
api-key=secret
api-readonly=yes
forward-zones-file=$(pwd)/recursor-service/forward-zones-file

socket-dir=/tmp/recursor-service
auth-zones=global.box.answer-cname-in-local.example.net=$(pwd)/recursor-service/global.box.answer-cname-in-local.example.net.zone,auth-zone.example.net=$(pwd)/recursor-service/auth-zone.example.net.zone,another-auth-zone.example.net=$(pwd)/recursor-service/another-auth-zone.example.net.zone
loglevel=9

EOF

cat > recursor-service2/recursor.conf <<EOF
local-port=5300
socket-dir=/tmp/recursor-service2
lowercase-outgoing=yes

EOF

cat > recursor-service3/recursor.conf << EOF
local-port=5301
socket-dir=/tmp/recursor-service3
lua-config-file=$(pwd)/recursor-service3/config.lua
lua-dns-script=$(pwd)/recursor-service3/script.lua

EOF

cat > recursor-service3/config.lua <<EOF
rpzFile("$(pwd)/recursor-service3/rpz.zone", {policyName="myRPZ"})
rpzFile("$(pwd)/recursor-service3/rpz2.zone", {policyName="mySecondRPZ"})
rpzFile("$(pwd)/recursor-service3/rpz3.zone", {policyName="cappedTTLRPZ", maxTTL=5})
rpzFile("$(pwd)/recursor-service3/rpz4.zone", {policyName="defPolicyTTL", defpol=Policy.Custom, defcontent="default.example.net", defttl=10, maxTTL=20})
rpzFile("$(pwd)/recursor-service3/rpz5.zone", {policyName="defPolicyCappedTTL", defpol=Policy.Custom, defcontent="default.example.net", defttl=50, maxTTL=20})
rpzFile("$(pwd)/recursor-service3/rpz6.zone", {policyName="defPolicyWithoutTTL", defpol=Policy.Custom, defcontent="default.example.net"})
rpzFile("$(pwd)/recursor-service3/rpz7.zone", {policyName="defPolicyWithoutTTLCapped", defpol=Policy.Custom, defcontent="default.example.net", maxTTL=50})
EOF

IFS=. read REV_PREFIX1 REV_PREFIX2 REV_PREFIX3 <<< $(echo $PREFIX) # This will bite us in the ass if we ever test on IPv6

cat > recursor-service3/rpz.zone <<EOF
\$TTL 2h;
\$ORIGIN domain.example.
@ SOA $SOA
@ NS ns.example.net.

arthur.example.net     CNAME .                   ; NXDOMAIN on apex
*.arthur.example.net   CNAME *.                  ; NODATA for everything below the apex
srv.arthur.example.net CNAME rpz-passthru.       ; Allow this name though
www.example.net        CNAME www2.example.net.   ; Local-Data Action
www3.example.net       CNAME www4.example.net.   ; Local-Data Action (to be changed in preresolve)
www5.example.net       A     192.0.2.15          ; Override www5.example.net.
trillian.example.net   CNAME .                   ; NXDOMAIN on apex, allows all sub-names (#4086)
*.wildcard-target.example.net          CNAME         *.walled-garden.example.net.         ; Special form of Local Data: a CNAME RR with a wildcarded target name

32.4.2.0.192.rpz-ip    CNAME rpz-drop.           ; www4.example.net resolves to 192.0.2.4, drop A responses with that IP

ns.hijackme.example.net.rpz-nsdname CNAME .      ; NXDOMAIN for anything hosted on ns.hijackme.example.net
ns.marvin.example.net.rpz-nsdname CNAME .        ; NXDOMAIN for anything hosted on ns.marvin.example.net (we disable RPZ in preresolve though)
32.24.$REV_PREFIX3.$REV_PREFIX2.$REV_PREFIX1.rpz-nsip CNAME . ; The IP for ns.lowercase-outgoing.example.net, should yield NXDOMAIN

EOF

cat > recursor-service3/rpz2.zone <<EOF
\$TTL 2h;
\$ORIGIN domain.example.
@ SOA $SOA
@ NS ns.example.net.

www5.example.net       A     192.0.2.25          ; Override www5.example.net.

EOF

cat > recursor-service3/rpz3.zone <<EOF
\$TTL 2h;
\$ORIGIN domain.example.
@ SOA $SOA
@ NS ns.example.net.

capped-ttl.example.net       50       IN      A     192.0.2.35          ; exceeds the maxTTL setting
unsupported.example.net      50       IN      CNAME rpz-unsupported.    ; unsupported target
unsupported2.example.net      50       IN      CNAME 32.3.2.0.192.rpz-unsupported.    ; also unsupported target
not-rpz.example.net           50       IN      CNAME rpz-not.com.                     ; this one is not a special RPZ target

EOF

cat > recursor-service3/rpz4.zone <<EOF
\$TTL 2h;
\$ORIGIN domain.example.
@ SOA $SOA
@ NS ns.example.net.

defpol-with-ttl.example.net       50       IN      A     192.0.2.35          ; will be overriden by the default policy and the default TTL

EOF

cat > recursor-service3/rpz5.zone <<EOF
\$TTL 2h;
\$ORIGIN domain.example.
@ SOA $SOA
@ NS ns.example.net.

defpol-with-ttl-capped.example.net       100       IN      A     192.0.2.35          ; will be overriden by the default policy and the default TTL (but capped by maxTTL)

EOF

cat > recursor-service3/rpz6.zone <<EOF
\$TTL 2h;
\$ORIGIN domain.example.
@ SOA $SOA
@ NS ns.example.net.

defpol-without-ttl.example.net       A     192.0.2.35          ; will be overriden by the default policy, but with the zone's TTL

EOF

cat > recursor-service3/rpz7.zone <<EOF
\$TTL 2h;
\$ORIGIN domain.example.
@ SOA $SOA
@ NS ns.example.net.

defpol-without-ttl-capped.example.net       A     192.0.2.35          ; will be overriden by the default policy, but with the zone's TTL capped by maxTTL

EOF

cat > recursor-service3/script.lua <<EOF
function prerpz(dq)
  if dq.qname:equal('www5.example.net') then
    dq:discardPolicy('myRPZ')
  end
  return true
end

function preresolve(dq)
  if dq.qname:equal("nxdomainme.example.net") then
    dq.rcode = pdns.NXDOMAIN
    return true
  end
  if dq.qname:equal("android.marvin.example.net") then
    dq.wantsRPZ = false -- disable RPZ
  end
  if dq.appliedPolicy.policyKind == pdns.policykinds.Custom then
    if dq.qname:equal("www3.example.net") then
      dq.appliedPolicy.policyCustom = "www2.example.net"
    end
  end
  return false
end
EOF

cat > recursor-service4/recursor.conf <<EOF
local-port=5302
socket-dir=/tmp/recursor-service4
packetcache-ttl=0
forward-zones=net.=$PREFIX.10;$PREFIX.11

EOF
