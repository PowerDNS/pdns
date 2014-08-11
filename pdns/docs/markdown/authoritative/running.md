# Running PDNS
PDNS is normally controlled via a SysV-style init.d script, often located in `/etc/init.d` or `/etc/rc.d/init.d`. This script accepts the following commands:

`monitor`:
Monitor is a special way to view the daemon. It executes PDNS in the foreground with a lot of logging turned on, which helps in determining startup problems. Besides running in the foreground, the raw PDNS control socket is made available. All external communication with the daemon is normally sent over this socket. While useful, the control console is not an officially supported feature. Commands which work are: **QUIT**, **SHOW \***, **SHOW varname**, **RPING**.

`start`:
Start PDNS in the background. Launches the daemon but makes no special effort to determine success, as making database connections may take a while. Use **status** to query success. You can safely run **start** many times, it will not start additional PDNS instances.

`restart`:
Restarts PDNS if it was running, starts it otherwise.

`status`:
Query PDNS for status. This can be used to figure out if a launch was successful. The status found is prefixed by the PID of the main PDNS process.

`stop`:
Requests that PDNS stop. Again, does not confirm success. Success can be ascertained with the **status** command.

`dump`:
Dumps a lot of statistics of a running PDNS daemon. It is also possible to single out specific variable by using the **show** command.

`show variable`:
Show a single statistic, as present in the output of the **dump**.

`mrtg`:
See the performance [monitoring](#XXX "Logging & Monitoring Authoritative Server performance").
