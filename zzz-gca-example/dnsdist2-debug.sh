echo "test-dnsdist2.sh - test dnsdist - debugging configuration"
echo ""
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SLASH="/"
CFG_FILE="dnsdist-debug.conf"
CONFIG_FILE=$DIR$SLASH$CFG_FILE
echo "current directory: " $DIR
echo ""
echo "configuration file: " $CONFIG_FILE
echo ""
echo "cd ../pdns/dnsdistdist"
echo ""
cd ../pdns/dnsdistdist
echo ""
###echo "listen on port 5200 for requests"
###echo ""
###./dnsdist --config=$CONFIG_FILE --local=0.0.0.0:5200

./dnsdist --config=$CONFIG_FILE
