PowerDNS Authoritative Nameserver
=================================

The PowerDNS Authoritative Server is a versatile nameserver which
supports a large number of backends. These backends can either be plain
zone files or be more dynamic in nature.

PowerDNS has the concepts of 'backends'. A backend is a datastore that
the server will consult that contains DNS records (and some metadata).
The backends range from database backends (:doc:`MySQL <backends/generic-mysql>`, :doc:`PostgreSQL <backends/generic-postgresql>`)
and :doc:`BIND zone files <backends/bind>` to :doc:`co-processes <backends/pipe>` and :doc:`JSON API's <backends/remote>`.

Multiple backends can be enabled in the configuration by using the
:ref:`setting-launch` option. Each backend can be configured separately.

See the :doc:`backend <backends/index>` documentation for more information.

This documentation is also available as a `PDF document <PowerDNS-Authoritative.pdf>`_.

Getting Started
---------------

* :doc:`Install the Authoritative Server <installation>`
* :doc:`Configure the Server <settings>`
* :doc:`Configure the backend(s) <backends/index>`

Getting Support
---------------
PowerDNS is an open source program so you may get help from the PowerDNS users' community or from its authors.
You may also help others (please do).

Public support is available via several different channels:

* This documentation
* `The mailing list <https://www.powerdns.com/mailing-lists.html>`_
* ``#powerdns`` on `irc.oftc.net <irc://irc.oftc.net/#powerdns>`_

The PowerDNS company can provide help or support you in private as well.
For first class and rapid support, please contact powerdns.support@powerdns.com, or see the `.com website <https://www.powerdns.com/support-services-consulting.html>`__.

My information is confidential, must I send it to the mailing list or discuss on IRC?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Yes, we have a support policy called `"Open Source Support: out in the open" <https://blog.powerdns.com/2016/01/18/open-source-support-out-in-the-open/>`_.

If you desire privacy, please consider entering a support relationship with us, in which case we invite you to contact powerdns.support.sales@powerdns.com.

I have a question!
^^^^^^^^^^^^^^^^^^
This happens, we're here to help!
Read below on how you can get help

What details should I supply?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Start out with stating what you think should be happening.
Quite often, wrong expectations are the actual problem.
Furthermore, your operating system, which version of PowerDNS you use and where you got it from (RPM, .DEB, tar.bz2).
If you compiled it yourself, what were the ``./configure`` parameters.

If possible, supply the actual name of your domain and the IP address of your server(s).

I found a bug!
^^^^^^^^^^^^^^
As much as we'd like to think we are perfect, bugs happen.
If you have found a bug, please file a bug report on `GitHub <https://github.com/PowerDNS/pdns/issues/new>`_.
Please fill in the template and we'll try our best to help you.

I found a security issue!
^^^^^^^^^^^^^^^^^^^^^^^^^
Please report this in private, see the :ref:`securitypolicy`.

I have a good idea for a feature!
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
We like to work on new things!
You can file a feature request on `GitHub <https://github.com/PowerDNS/pdns/issues/new>`_.

