# PDNS Keyroll Daemon

## Configuration

See `pdns-keyroller.conf.example`

## pdns-keyroller

Main util that should be run periodically (crontab job for instance). Will list all configured automatic rolls
and proceed to scheduled operations (start a new roll, advanced roll steps).

## pdns-keyroller-ctl

You can configure a zone for automatic keyroll using `pdns-keyroller-ctl`

    # use the domain defaults defined in the configuration file
    $ pdns-keyroller-ctl configs roll example.com

    # Specify ZSK and KSK rollover frequency
    $ pdns-keyroller-ctl configs roll example.com \
        --zsk-frequency 6w --ksk-frequency never

    # Overwrite an existing configuration
    $ pdns-keyroller-ctl configs roll example.com --force \
        --zsk-frequency 6w --ksk-frequency never

    # Look at an existing configuration
    $ pdns-keyroller-ctl configs show example.com


You can now list the configured zones and see last roll informations using

    # use the domain defaults defined in the configuration file
    $ pdns-keyroller-ctl configs
    INFO:pdns-keyroller:example.com. is not rolling. Last KSK roll was
    never and the last ZSK roll was never

Some steps require manual actions such as KSK roll and publishing new DS to the parent. You can list such zones

    $ pdns-keyroller-ctl roll waiting

And advance to the next step when you have published the new DS, waiting `TTL` seconds

    $ pdns-keyroller-ctl roll step <ZONE> <TTL>

Removed :
- NSEC3 param roll
- keystyle roll

## Dev environment

Setting up the environment

    $ virtualenv .venv
    $ source .venv/bin/activate
    $ pip install -r requirements.txt


## Packaging

For now, only `centos-7` `<target>` is supported

    $ git submodule update --init --recursive
    $ bash builder/build.sh <target>

## Meta content

Zone configuration and roll status is persisted through the domain metadata system provided by the authoritative server. The format used for the content is JSON.

### Zone configuration

Zone configuration is attached as a meta data with the key `X-PDNSKEYROLLER-CONFIG`

``` json
    {
       "key_style" : "split",
       "ksk_algo" : 13,
       "ksk_frequency" : "6w",
       "ksk_keysize" : 3069,
       "ksk_method" : "prepublish",
       "version" : 1,
       "zsk_algo" : 13,
       "zsk_frequency" : 0,
       "zsk_keysize" : 3069,
       "zsk_method" : "prepublish"
    }
```

* `version` : this json format version identifier
* `key_style` : `single` or `split` depending on the number of keys
* `xsk_algo` : algorithm to roll as name or number, see below
* `xsk_frequency` : the rate at which to roll the keys
* `xsk_keysize` : keysize in bits
* `xsk_method` : strategy for the rollover (for now, only `prepublish` is supported)

Frequency is parsed as time expressions like the following :

* `6 weeks`, `6w`
* `120 days`, `120d`
* `1w 3d 2h 32m`

Supported algorithms are :

*  1: `RSAMD5`
*  2: `DH`
*  3: `DSA`
*  5: `RSASHA1`
*  6: `DSA-NSEC3-SHA1`
*  7: `RSASHA1-NSEC3-SHA1`
*  8: `RSASHA256`
* 10: `RSASHA512`
* 12: `ECC-GOST`
* 13: `ECDSAP256`
* 14: `ECDSAP384`
* 15: `ED25519`
* 16: `ED448`

### Roll status

Roll status is attached as a meta data with the key `X-PDNSKEYROLLER-STATE`

``` json
{
   "current_roll" : {
      "__instance_type__" : [
         "pdnskeyroller.prepublishkeyroll",
         "PrePublishKeyRoll"
      ],
      "attributes" : {
         "algo" : "ECDSAP256",
         "complete" : false,
         "current_step" : 1,
         "current_step_datetime" : 1650635957.26533,
         "keytype" : "ksk",
         "new_keyid" : 6,
         "old_keyids" : [
            4
         ],
         "rolltype" : "prepublish",
         "step_datetimes" : [
            1650632357.26229
         ]
      }
   },
   "last_ksk_roll_datetime" : 0,
   "last_zsk_roll_datetime" : 0,
   "version" : 1
}
```

* `current_roll` contains informations about the actual roll
* `current_roll.complete` tells if the roll is finished
* `current_roll.current_step` is the step number
* `current_roll.current_step_datetime` tells when the step has to be performed
* `current_roll.new_keyid` contains the identifier of the new generated key when `old_keyids` contains the keys that are being replaced
* `current_roll.step_datetimes` contains timestamp at which the steps have been performed
* `last_xsk_roll_datetime` contains the timestamp of the last keyroll
* `version` contains a document format identifier
