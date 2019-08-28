.. _Misc:

Other functions
^^^^^^^^^^^^^^^

.. function:: pdnslog(message[, loglevel])

  Log the `message` at the daemon level

  :param string message: The message to log
  :param int loglevel: The urgency level of the message. Defaults to `pdns.loglevels.Warning`

  You can use the following constants as log levels :

  - `pdns.loglevels.Alert`
  - `pdns.loglevels.Critical`
  - `pdns.loglevels.Debug`
  - `pdns.loglevels.Emergency`
  - `pdns.loglevels.Info`
  - `pdns.loglevels.Notice`
  - `pdns.loglevels.Warning`
  - `pdns.loglevels.Error`

.. function:: pdnsrandom([upper_bound])

  Get a random number.

  :param int upper_bound: The upper bound. You will get a random number below this upper bound.
