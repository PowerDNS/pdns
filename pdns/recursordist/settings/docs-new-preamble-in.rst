PowerDNS Recursor New Style (YAML) Settings
===========================================

Each setting can appear on the command line, prefixed by ``--`` and using the old style name, or in configuration files.
Settings on the command line are processed after the file-based settings are processed.

.. note::
   Starting with version 5.0.0., :program:`Recursor` supports a new YAML syntax for configuration files
   as described here.
   A configuration using the old style syntax can be converted to a YAML configuration using the instructions in :doc:`appendices/yamlconversion`.
   In a future release support for the "old-style" settings will be dropped.


YAML settings file
------------------
Please refer to e.g. `<https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html>`_
for a description of YAML syntax.

A :program:`Recursor` configuration file has several sections. For example, ``incoming`` for
settings related to receiving queries and ``dnssec`` for settings related to DNSSEC processing.

An example :program:`Recursor` YAML configuration file looks like:

.. code-block:: yaml

  dnssec:
    log_bogus: true
  incoming:
    listen:
      - 0.0.0.0:5301
      - '[::]:5301'
  recursor:
    extended_resolution_errors: true
    forward_zones:
      - zone: example.com
        forwarders:
          - 127.0.0.1:5301
  outgoing:
    query_local_address:
      - 0.0.0.0
      - '::'
  logging:
    loglevel: 6

Take care when listing IPv6 addresses, as characters used for these are special to YAML.
If in doubt, quote any string containing ``:``, ``[`` or ``]`` and use (online) tools to check your YAML syntax.
Specify an empty sequence using ``[]``.

The main setting file is called ``recursor.yml`` and will be processed first.
This settings file might refer to other files via the `recursor.include_dir`_ setting.
The next section will describe how settings specified in multiple files are merged.

Merging multiple setting files
------------------------------
If `recursor.include_dir`_ is set, all ``.yml`` files in it will be processed in alphabetical order, modifying the  settings processed so far.

For simple values like an boolean or number setting, a value in the processed file will overwrite an existing setting.

For values of type sequence, the new value will *replace* the existing value if the existing value is equal to the ``default`` or if the new value is marked with the ``!override`` tag.
Otherwise, the existing value will be *extended* with the new value by appending the new sequence to the existing.

For example, with the above example ``recursor.yml`` and an include directory containing a file ``extra.yml``:

.. code-block:: yaml

  dnssec:
    log_bogus: false
  recursor:
    forward_zones:
      - zone: example.net
        forwarders:
          - '::1'
  outgoing:
     query_local_address: !override
       - 0.0.0.0
     dont_query: []

After merging, ``dnssec.log_bogus`` will be ``false``, the sequence of ``recursor.forward_zones`` will contain 2 zones and the ``outgoing`` addresses used will contain one entry, as the ``extra.yml`` entry has overwritten the existing one.

``outgoing.dont-query`` has a non-empty sequence as default value. The main ``recursor.yml`` did not set it, so before processing ``extra.yml`` had the default value.
After processing ``extra.yml`` the value will be set to the empty sequence, as existing default values are overwritten by new values.

.. warning::
   The merging process does not process values deeper than the second level.
   For example if the main ``recursor.yml`` specified a forward zone

   .. code-block:: yaml

     forward_zones:
       - zone: example.net
         forwarders:
           - '::1'

   and another settings file contains

   .. code-block:: yaml

     forward_zones:
       - zone: example.net
         forwarders:
           - '::2'

   The result will *not* be a a single forward with two IP addresses, but two entries for ``example.net``.
   It depends on the specific setting how the sequence is processed further.
   In the future we might add a check for this case.

Socket Address
^^^^^^^^^^^^^^
A socket address is either an IP or and IP:port combination
For example:

.. code-block:: yaml

   some_key: 127.0.0.1
   another_key: '[::1]:8080'

Subnet
^^^^^^
A subnet is a single IP address or an IP address followed by a slash and a prefix length.
If no prefix length is specified, ``/32`` or ``/128`` is assumed, indicating a single IP address.
Subnets can also be prefixed with a ``!``, specifying negation.
This can be used to deny addresses from a previously allowed range.

For example, ``alow-from`` takes a sequence of subnets:

.. code-block:: yaml

   allow_from:
     - '2001:DB8::/32'
     - 128.66.0.0/16
     - !128.66.1.2

In this case the address ``128.66.1.2`` is excluded from the addresses allowed access.

Forward Zone
^^^^^^^^^^^^
A forward zone is defined as:

.. code-block:: yaml

  zone: zonename
  forwarders:
    - Socket Address
    - ...
  recurse: Boolean, default false
  allow_notify:  Boolean, default false

An example of a ``forward_zones`` entry, which consists of a sequence of forward zone entries:

.. code-block:: yaml

  - zone: example1.com
    forwarders:
      - 127.0.0.1
      - 127.0.0.1:5353
      - '[::1]53'
  - zone: example2.com
    forwarders:
      - '::1'
    recurse: true
    notify_allowed: true


Auth Zone
^^^^^^^^^
A auth zone is defined as:

.. code-block:: yaml

  zone: name
  file: filename

An example of a ``auth_zones`` entry, consisting of a sequence of auth zones:

.. code-block:: yaml

   auth_zones:
     - zone: example.com
       file: zones/example.com.zone
     - zone: example.net
       file: zones/example.net.zone

The YAML settings
-----------------

