Carbon export
=============

.. function:: carbonServer(serverIP [, ourname[, interval[, namespace,[ instance]]]])

  Exort statistics to a Carbon / Graphite / Metronome server.

  :param string serverIP: Indicates the IP address where the statistics should be sent
  :param string ourname: An optional string specifying the hostname that should be used
  :param int interval: An optional unsigned integer indicating the interval in seconds between exports
  :param string namespace: An optional string specifying the namespace name that should be used
  :param string instance: An optional string specifying the instance name that should be used

