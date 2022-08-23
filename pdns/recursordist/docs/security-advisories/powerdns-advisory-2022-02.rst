PowerDNS Security Advisory 2022-02: incomplete exception handling related to protobuf message generation
========================================================================================================

- CVE: CVE-2022-37428
- Date: 23th of August 2022.
- Affects: PowerDNS Recursor up to and including 4.5.9, 4.6.2 and 4.7.1
- Not affected: PowerDNS Recursor 4.5.10, 4.6.3 and 4.7.2
- Severity: Medium
- Impact: Denial of service
- Exploit: This problem can be triggered by a remote attacker with access to the recursor if protobuf logging is enabled
- Risk of system compromise: None
- Solution: Upgrade to patched version, disable protobuf logging of responses

This issue only affects recursors which have protobuf logging enabled using the

- ``protobufServer`` function with ``logResponses=true`` or
- ``outgoingProtobufServer`` function with ``logResponses=true``

If either of these functions is used without specifying ``logResponses``, its value is ``true``.
An attacker needs to have access to the recursor, i.e. the remote IP must be in the access control list.
If an attacker queries a name that leads to an answer with specific properties, a protobuf message might be generated that causes an exception. The code does not handle this exception correctly, causing a denial of service.
