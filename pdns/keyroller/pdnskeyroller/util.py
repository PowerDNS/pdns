import pdnsapi.api
import logging

logger = logging.getLogger()

"""
Helper functions for the keyrollers and the daemon
"""

DNSKEY_ALGO_TO_MNEMONIC = {
        1: "RSAMD5",
        2: "DH",
        3: "DSA",
        5: "RSASHA1",
        6: "DSA-NSEC3-SHA1",
        7: "RSASHA1-NSEC3-SHA1",
        8: "RSASHA256",
        10: "RSASHA512",
        12: "ECC-GOST",
        13: "ECDSAP256",
        14: "ECDSAP384",
        15: "ED25519",
        16: "ED448",
    }

DNSKEY_MNEMONIC_TO_ALGO = {v: k for k, v in DNSKEY_ALGO_TO_MNEMONIC.items()}

def parse_algo(algo):
    res = 0
    try:
        res = int(algo)
    except:
        res = DNSKEY_MNEMONIC_TO_ALGO.get(algo.upper())

    if DNSKEY_ALGO_TO_MNEMONIC.get(res) is None:
        raise Exception('Unknown key algorithm {}'.format(algo))

    return res


def validate_api(api):
    if not isinstance(api, pdnsapi.api.PDNSApi):
        raise Exception('api is not a PDNSApi')

def validate_keytype(keytype):
    keytype = keytype.lower()
    if keytype not in ('ksk', 'zsk', 'csk'):
        raise Exception('{} is not a valid key type'.format(keytype))


def get_keystyle(zone, api):
    """
    Determines the current style of DNSSEC keying for ``zone``.
    The style will be one of:

    * single (one or more CSKs)
    * split (KSK(s) and ZSK(s) exist)
    * mixed (There are CSK(s), KSK(s) and ZSK(s))

    :param string zone: The zone to check
    :param pdnsapi.api.PDNSApi api: The API endpoint to use
    :return: The description of the current key-style
    :rtype: string
    """
    validate_api(api)
    cryptokeys = api.get_cryptokeys(zone)

    if not len(cryptokeys):
        raise Exception('No cryptokeys for zone {}'.format(zone))

    got_ksk = any([cryptokey.keytype.lower() == 'ksk' for cryptokey in cryptokeys])
    got_zsk = any([cryptokey.keytype.lower() == 'zsk' for cryptokey in cryptokeys])
    got_csk = any([cryptokey.keytype.lower() == 'csk' for cryptokey in cryptokeys])

    if got_csk and not any([got_ksk, got_zsk]):
        return 'single'
    if all([got_ksk, got_zsk]) and not got_csk:
        return 'split'
    if all([got_ksk, got_zsk, got_csk]):
        return 'mixed'


def get_keys_of_type(zone, api, keytype):
    """
    Returns all the keys of type ``keytype`` for ``zone``

    :param string zone: The zone to get the keys from
    :param pdnsapi.api.PDNSApi api: The API endpoint to use
    :param string keytype: 'ksk', 'zsk' or 'csk'
    :return: All the keys of the requested type
    :rtype: list(pdnsapi.zone.CryptoKey)
    """
    validate_api(api)
    keytype = keytype.lower()
    validate_keytype(keytype)

    cryptokeys = api.get_cryptokeys(zone)
    return [k for k in cryptokeys if k.keytype == keytype]
