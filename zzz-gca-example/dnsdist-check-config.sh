echo "dnsdist-check-config.sh - check dnsdist config file"
echo ""
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SLASH="/"
CFG_FILE="dnsdist.conf"
CONFIG_FILE=$DIR$SLASH$CFG_FILE
echo "current directory: " $DIR
echo ""
echo "configuration file: " $CONFIG_FILE
echo ""
echo "cd ../pdns/dnsdistdist"
echo ""
cd ../pdns/dnsdistdist
echo ""
./dnsdist --config=$CONFIG_FILE --check-config
echo ""

