#!/bin/sh
set -e
set -x

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
cd configs

cat > run-auth <<EOF
#!/bin/sh
$AUTHRUN
EOF
chmod +x run-auth

mkdir recursor-service
cat > recursor-service/run <<EOF
#!/bin/sh
$RECRUN
EOF
chmod +x recursor-service/run

cat > recursor-service/hintfile << EOF
.                        3600 IN NS  ns.root.
ns.root.                 3600 IN A   $PREFIX.8
EOF

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
EOF

mkdir $PREFIX.11
cp $PREFIX.10/example.net.zone $PREFIX.11/

### plain delegated zone, no surprises
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
function prequery ( dnspacket )
    qname, qtype = dnspacket:getQuestion()
    if qtype == pdns.A and qname == "www.marvin.example.net"
    then
        dnspacket:setRcode(pdns.NXDOMAIN)
        ret = {}
        ret[1] = {qname=qname, qtype=pdns.CNAME, content="android.marvin.example.net", place=1}
        ret[2] = {qname="marvin.example.net", qtype=pdns.SOA, content="$SOA", place=2}
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
function prequery ( dnspacket )
    qname, qtype = dnspacket:getQuestion()
    if qtype == pdns.A and qname == "www.trillian.example.net"
    then
        dnspacket:setRcode(pdns.NXDOMAIN)
        ret = {}
        ret[1] = {qname=qname, qtype=pdns.CNAME, content="www2.arthur.example.net", place=1}
        ret[2] = {qname="", qtype=pdns.SOA, content="$SOA", place=2}
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

function prequery ( dnspacket )
    i = i + 1
    qname, qtype = dnspacket:getQuestion()
    if qtype == pdns.A and string.sub(qname, -24) == ".www.1.ghost.example.net"
    then
        dnspacket:setRcode(pdns.NOERROR)
        ret = {}
        -- www.1.ghost.example.net. 20  IN  A   192.0.2.7
        ret[1] = {qname=qname, qtype=pdns.A, content="192.0.2.7", ttl=20, place=1}
        -- 1.ghost.example.net. 20  IN  NS  ns.1.ghost.example.net.
        ret[2] = {qname="1.ghost.example.net", qtype=pdns.NS, content="ns"..i..".1.ghost.example.net", ttl=20, place=2}
        -- ns.1.ghost.example.net.  20  IN  A   10.0.3.18
        ret[3] = {qname="ns"..i..".1.ghost.example.net", qtype=pdns.A, content="10.0.3.18", ttl=20, place=3}
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
function prequery ( dnspacket )
    qname, qtype = dnspacket:getQuestion()
    if qtype == pdns.A and string.sub(qname, -24) == ".www.2.ghost.example.net"
    then
        dnspacket:setRcode(pdns.NOERROR)
        ret = {}
        ret[1] = {qname=qname, qtype=pdns.A, content="192.0.2.8", ttl=20, place=1}
        ret[2] = {qname="2.ghost.example.net", qtype=pdns.NS, content="ns.2.ghost.example.net", ttl=20, place=2}
        ret[3] = {qname="ns.2.ghost.example.net", qtype=pdns.A, content="10.0.3.19", ttl=20, place=3}
        dnspacket:addRecords(ret)
        return true
    end
    return false
end
EOF

for dir in $PREFIX.*
do
    cat > $dir/pdns.conf <<EOF
launch=bind
daemon=no
local-address=$dir
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
    ln -s ../run-auth $dir/run
done

cat > recursor-service/recursor.conf << EOF
socket-dir=$(pwd)/recursor-service
EOF