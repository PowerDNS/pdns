echo "test dnsdist with nocookie option to allow cache hits"
echo "dig @127.0.0.1 -p 5200 +nocookie google.com"
echo ""
dig @127.0.0.1 -p 5200 +nocookie google.com
