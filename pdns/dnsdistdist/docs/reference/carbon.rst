Carbon export
=============

.. function:: carbonServer(serverIP [, ourname], [interval])

  Exort statistics to a Carbon / Graphite / Metronome server.

  :param string serverIP: Indicates the IP address where the statistics should be sent
  :param string ourname: An optional string specifying the hostname that should be used
  :param int interval: An optional unsigned integer indicating the interval in seconds between exports

