# Random Backend

* Native: Yes
* Master: No
* Slave: No
* Superslave: No
* Autoserial: No
* Case: Depends
* DNSSEC: Yes, no key storage
* Disabled data: No
* Comments: No
* Module name: built in
* Launch: random

This is a very silly backend which is discussed in the [Backends writer's guide](../appendix/backend-writers-guide.md#simple-backends) as a demonstration on how to write a PowerDNS backend.

This backend knows about only one hostname, and only about its IP address at that. With every query, a new random IP address is generated.

It only makes sense to load the random backend in combination with a regular backend. This can be done by prepending it to the [`launch`](settings.md#launch) instruction, such as `launch=random,gmysql`.

## Configuration Parameters
### `random-hostname`
* String

Hostname for which to supply a random IP address.
