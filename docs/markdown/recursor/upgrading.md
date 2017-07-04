Before upgrading, it is advised to read the [changelog](../changelog.md).
When upgrading several versions, please read **all** notes applying to the upgrade.

# 4.0.5 to 4.0.6

One default was changed:

 - [`use-incoming-edns-subnet`](settings.md#use-incoming-edns-subnet) defaults to off, was on before

# 4.0.3 to 4.0.4
One setting has been added to limit the risk of overflowing the stack:

 - [`max-recursion-depth`](settings.md#max-recursion-depth) defaults to 40 and was unlimited before

# 4.0.0 to 4.0.1
Two settings have changed defaults, these new defaults decrease CPU usage:

 - [`root-nx-trust`](settings.md#root-nx-trust) changed from `no` to `yes`
 - [`log-common-errors`](settings.md#log-common-errors) changed from `yes` to `no`
