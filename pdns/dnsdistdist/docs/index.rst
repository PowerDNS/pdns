dnsdist Overview
================

:program:`dnsdist` is a highly DNS-, DoS- and abuse-aware loadbalancer.
Its goal in life is to route traffic to the best server, delivering top performance to legitimate users while shunting or blocking abusive traffic.

:program:`dnsdist` is dynamic, its configuration can be changed at runtime via a :doc:`console-like interface <guides/console>`.
It exposes :doc:`metrics <statistics>` that can be exported via Carbon, Prometheus, an HTTP API and the console.

Until 2.0.0 the configuration was written in `Lua <https://lua.org>`_, but it is now possible to write the configuration in :doc:`yaml <reference/yaml-settings>` as well.

A configuration to balance DNS queries to several backend servers:

.. code-block:: lua

   newServer({address="2620:fe::fe"})
   newServer({address="2620:fe::9"})
   newServer({address="9.9.9.9"})
   newServer({address="2001:db8::1"})
   newServer({address="[2001:db8::2]:5300", name="dns1"})
   newServer("192.0.2.1")

Or in ``yaml``:

.. code-block:: yaml

  backends:
    - address: "2620:fe::fe"
      protocol: Do53
    - address: "2620:fe::9"
      protocol: Do53
    - address: "9.9.9.9"
      protocol: Do53
    - address: "2001:db8::1"
      protocol: Do53
    - address: "[2001:db8::1]:5300"
      name: "dns1"
      protocol: Do53
    - address: "192.0.2.1"
      protocol: Do53


Running dnsdist
---------------

If you have not worked with dnsdist before, here are some resources to get you going:

* :doc:`Install dnsdist <install>`.
* To get a feeling for how it works, see the :doc:`Quickstart Guide <quickstart>`.
* :doc:`running`
* The :doc:`rules-actions` page covers how to apply policies to traffic
* There are several :doc:`guides/index` about the different features and options
* :doc:`advanced/index` describes some of the more advanced features
* :doc:`reference/index` has all the configuration and object information

Questions, requests or comments?
--------------------------------

There are several ways to reach us:

* The `dnsdist mailing-list <https://mailman.powerdns.com/mailman/listinfo/dnsdist>`_
* #powerdns on `irc.oftc.net <irc://irc.oftc.net/#powerdns>`_

The Open-Xchange/PowerDNS company can provide help or support you in private as well.
Please `contact PowerDNS <https://www.powerdns.com/contact-us>`__.

This documentation is also available as a `PDF document <dnsdist.pdf>`_.
