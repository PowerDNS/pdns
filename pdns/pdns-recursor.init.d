#!/bin/sh
### BEGIN INIT INFO
# Provides:          pdns-recursor
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: PowerDNS Recursor
### END INIT INFO
# chkconfig: - 80 75
# description: pdns_recursor is a versatile high performance recursing nameserver

BINARYPATH=/usr/bin
SBINARYPATH=/usr/sbin
SOCKETPATH=/var/run

pdns_server=$SBINARYPATH/pdns_recursor

[ -f "$pdns_server" ] || exit 0

doPC()
{
	ret=`$BINARYPATH/rec_control $EXTRAOPTS $1 $2 2> /dev/null`
}


doPC ping
NOTRUNNING=$?

case "$1" in
	status)
		if test "$NOTRUNNING" = "0" 
		then 
			echo "running"
			exit 0
		else
			echo "not running"
			# Note: 3 is a white lie. We currently don't *really*
			# know that it's not running, or if the ping failed for
			# other reasons (= 4).
			exit 3
		fi 
	;;	

	stop)
		echo -n "Stopping PowerDNS recursing nameserver: "
		if test "$NOTRUNNING" = "0" 
		then 
			doPC quit
			echo $ret
		else
			echo "not running"
			exit 1
		fi 
	;;		


	force-stop)
		echo -n "Stopping PowerDNS recursing nameserver: "
		killall -v -9 $pdns_server
		echo "killed"
	;;

	start)
		echo -n "Starting PowerDNS recursing nameserver: "
		if test "$NOTRUNNING" = "0" 
		then 
			echo "already running"
			exit 1
		else
			$pdns_server --daemon 
			if test "$?" = "0"
			then
				echo "started"	
			fi
		fi 
	;;		

	force-reload | restart)
		echo -n "Restarting PowerDNS recursing nameserver: "
		echo -n stopping and waiting.. 
		doPC quit
		sleep 3
		echo done
		$0 start
	;;

	monitor)
		if test "$NOTRUNNING" = "0" 
		then 
			echo "already running"
		else
			$pdns_server --daemon=no --quiet=no --loglevel=9
		fi 
	;;

	*)
	echo pdns [start\|stop\|force-reload\|restart\|status\|monitor]

	;;
esac


