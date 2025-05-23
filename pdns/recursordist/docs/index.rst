Introduction
============

.. image:: common/powerdns-logo-500px.png
    :align: center
    :alt: PowerDNS Logo

The PowerDNS Recursor is a high-performance DNS recursor with built-in scripting capabilities.
It is known to power the resolving needs of over 150 million internet connections.

The documentation is only for the 4.1 and higher series, users of
older versions are urged to read :ref:`EOL` and upgrade!

This documentation is also available as a `PDF document <PowerDNS-Recursor.pdf>`_.

Notable features
----------------

- Can handle tens of thousands of concurrent questions. A quad Xeon 3GHz has been measured functioning very well at 400000 real life replayed packets per second.
- Relies heavily on Standard C++ Library infrastructure.
- Powered by a highly modern DNS packet parser that should be resistant against many forms of buffer overflows.
- Best spoofing protection that we know about, involving both source port randomisation and spoofing detection.
- Uses 'connected' UDP sockets which allow the recursor to react quickly to unreachable hosts or hosts for which the server is running, but the nameserver is down. This makes the recursor faster to respond in case of misconfigured domains, which are sadly very frequent.
- Special support for \*BSD, Linux and Solaris stateful multiplexing (kqueue, epoll, completion ports, /dev/poll).
- Very fast, and contains innovative query-throttling code to save time talking to obsolete or broken nameservers.
- Code is written linearly, sequentially, which means that there are no problems with 'query restart' or anything.
- Does DNSSEC validation
- Is highly scriptable in `Lua <http://lua.org>`_

Getting support
---------------
PowerDNS is an open source program so you may get help from the PowerDNS users' community or from its authors.
You may also help others (please do).

Public support is available via several different channels:

  * This documentation
  * `The mailing list <https://www.powerdns.com/mailing-lists.html>`_
  * ``#powerdns`` on `irc.oftc.net <irc://irc.oftc.net/#powerdns>`_

The Open-Xchange/PowerDNS company can provide help or support you in private as well.
Please `contact PowerDNS <https://www.powerdns.com/contact-us>`__.

My information is confidential, must I send it to the mailing list, discuss it on IRC, or post it in a GitHub ticket?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Yes, we have a support policy called `"Open Source Support: out in the open" <https://blog.powerdns.com/2016/01/18/open-source-support-out-in-the-open/>`_.

If you desire privacy, please consider entering a support relationship with us, in which case we invite you to `contact PowerDNS <https://www.powerdns.com/contact-us>`__.

I have a question!
^^^^^^^^^^^^^^^^^^
This happens, we're here to help!
Read below on how you can get help

What details should I supply?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Start out with stating what you think should be happening.
Quite often, wrong expectations are the actual problem.
Furthermore, your operating system, which version of PowerDNS you use and where you got it from (RPM, .DEB, tar.bz2).
If you :doc:`compiled <appendices/compiling>` it yourself, what were the ``./configure`` parameters.

If possible, supply the actual name of your domain and the IP address of your server(s).

I found a bug!
^^^^^^^^^^^^^^
As much as we'd like to think we are perfect, bugs happen.
If you have found a bug, please file a bug report on `GitHub bug report <https://github.com/PowerDNS/pdns/issues/new?template=bug_report.md>`_.
Please fill in the template and we'll try our best to help you.

I found a security issue!
^^^^^^^^^^^^^^^^^^^^^^^^^
Please report this in private, see the :ref:`securitypolicy`.

I have a good idea for a feature!
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
We like to work on new things!
You can file a feature request on `GitHub feature request <https://github.com/PowerDNS/pdns/issues/new?template=feature_request.md>`_.

Third party software
--------------------
We use code from the project listed below.

Protozero
^^^^^^^^^
protozero copyright (c) Mapbox.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
