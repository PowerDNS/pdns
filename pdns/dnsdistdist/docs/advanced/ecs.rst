Using EDNS Client Subnet
------------------------

In order to provide the downstream server with the address of the real client, or at least the one talking to dnsdist, the ``useClientSubnet`` parameter can be used when creating a :func:`new server <newServer>`.
This parameter indicates whether an EDNS Client Subnet option should be added to the request.
If the incoming request already contains an EDNS Client Subnet value, it will not be overriden unless :func:`setECSOverride` is set to ``true``.
The default source prefix-length is 24 for IPv4 and 56 for IPv6, meaning that for a query received from 192.0.2.42, the EDNS Client Subnet value sent to the backend will be 192.0.2.0.
This can be changed with :func:`setECSSourcePrefixV4` and :func:`setECSSourcePrefixV6`.

In addition to the global settings, rules and Lua bindings can alter this behavior per query:

 * calling :func:`DisableECSAction` or setting ``dq.useECS`` to ``false`` prevents the sending of the ECS option.
 * calling :func:`ECSOverrideAction` or setting ``dq.ecsOverride`` will override the global :func:`setECSOverride` value.
 * calling :func:`ECSPrefixLengthAction(v4, v6)` or setting ``dq.ecsPrefixLength`` will override the global :func:`setECSSourcePrefixV4()` and :func:`setECSSourcePrefixV6()` values.

In effect this means that for the EDNS Client Subnet option to be added to the request, ``useClientSubnet`` should be set to ``true`` for the backend used (default to ``false``) and ECS should not have been disabled by calling :func:`DisableECSAction` or setting ``dq.useECS`` to ``false`` (default to true).

Note that any trailing data present in the incoming query is removed by default when an OPT (or XPF) record has to be inserted. This behaviour can be modified using :func:`setPreserveTrailingData()`.
