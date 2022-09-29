import pdnsapi.api
from pdnskeyroller import PDNSKEYROLLER_CONFIG_metadata_kind
from pytimeparse.timeparse import timeparse
import pdnsapi.metadata
import json_tricks.nonp as json_tricks
from pdnskeyroller.util import (parse_algo)

DOMAINCONFIG_VERSION = 1

def from_api(zone, api):
    """
    Retrieves a keyroller configuration for zone ``zone`` from the api ``api``

    :param string zone: The zone to retrieve the Config for
    :param pdnsapi.api.PDNSApi api: The API to use
    :return: The configuration
    :rtype: :class:`DomainConfig`
    :raises: FileNotFoundError if ``zone`` does not have a roller config
    """
    if not isinstance(api, pdnsapi.api.PDNSApi):
        raise Exception('api is not a PDNSApi')

    metadata = api.get_zone_metadata(zone, PDNSKEYROLLER_CONFIG_metadata_kind)

    if metadata.empty():
        raise FileNotFoundError

    if len(metadata.metadata) > 1:
        raise Exception("More than one {} Domain Metadata found for {}!".format(PDNSKEYROLLER_CONFIG_metadata_kind,
                                                                                zone))
    try:
        state = json_tricks.loads(metadata.metadata[0])
    except Exception as e:
        raise ValueError(e)

    return DomainConfig(**state)

def to_api(zone, api, config):
    """

    :param zone:
    :param api:
    :param config:
    :return:
    """
    if not isinstance(api, pdnsapi.api.PDNSApi):
        raise Exception('api must be a PDNSApi instance, not a {}'.format(type(api)))
    if not isinstance(config, DomainConfig):
        raise Exception('config must be a DomainConfig instance, not a {}'.format(type(config)))

    api.set_zone_metadata(zone, PDNSKEYROLLER_CONFIG_metadata_kind, str(config))


class DomainConfig:
    __version = DOMAINCONFIG_VERSION
    __ksk_frequency = 0
    __ksk_algo = 13
    __ksk_keysize = 3096
    __ksk_method = "prepublish"
    __zsk_frequency = "6w"
    __zsk_algo = 13
    __zsk_keysize = 3096
    __zsk_method = "prepublish"
    __key_style = "split"

    def __init__(self, version=DOMAINCONFIG_VERSION, ksk_frequency=0, ksk_algo=13, ksk_keysize=3096, ksk_method="prepublish",
                 zsk_frequency="6w", zsk_algo=13, zsk_keysize=3096, zsk_method="prepublish", key_style="split", **kwargs):

        self.version = version

        self.ksk_frequency = ksk_frequency
        self.ksk_algo = ksk_algo
        self.ksk_keysize = ksk_keysize
        self.ksk_method = ksk_method

        self.zsk_frequency = zsk_frequency
        self.zsk_algo = zsk_algo
        self.zsk_keysize = zsk_keysize
        self.zsk_method = zsk_method

        self.key_style = key_style
        if kwargs:
            logger.warning('Unknown keys passed: {}'.format(', '.join(
                [k for k, v in kwargs.items()])))

    @property
    def ksk_frequency(self):

        return self.__ksk_frequency

    @ksk_frequency.setter
    def ksk_frequency(self, value):
        if value != "never" and value != 0:
            if timeparse(value) is None:
                raise SyntaxError('Can not parse value "%s" to as timedelta' % value)
            self.__ksk_frequency = value
        else:
            self.__ksk_frequency = 0

    @property
    def ksk_algo(self):
        return self.__ksk_algo

    @ksk_algo.setter
    def ksk_algo(self, value):
        self.__ksk_algo = parse_algo(value)

    @property
    def ksk_keysize(self):
        return self.__ksk_keysize

    @ksk_keysize.setter
    def ksk_keysize(self, value):
        self.__ksk_keysize = value

    @property
    def ksk_method(self):
        return self.__ksk_method

    @ksk_method.setter
    def ksk_method(self, value):
        self.__ksk_method = value

    @property
    def zsk_frequency(self):
        return self.__zsk_frequency

    @zsk_frequency.setter
    def zsk_frequency(self, value):
        if value != "never" and value != 0:
            if timeparse(value) is None:
                raise SyntaxError('Can not parse value "%s" to as timedelta' % value)
            self.__zsk_frequency = value
        else:
            self.__zsk_frequency = 0

    @property
    def zsk_algo(self):
        return self.__zsk_algo

    @zsk_algo.setter
    def zsk_algo(self, value):
        self.__zsk_algo = parse_algo(value)

    @property
    def zsk_keysize(self):
        return self.__zsk_keysize

    @zsk_keysize.setter
    def zsk_keysize(self, value):
        self.__zsk_keysize = value

    @property
    def zsk_method(self):
        return self.__zsk_method

    @zsk_method.setter
    def zsk_method(self, value):
        self.__zsk_method = value

    @property
    def key_style(self):
        return self.__key_style

    @key_style.setter
    def key_style(self, value):
        if value not in ('single', 'split'):
            raise Exception('Invalid key_style: {}'. format(value))
        self.__key_style = value

    @property
    def version(self):
        return self.__version

    @version.setter
    def version(self, val):
        if val != 1:
            raise Exception('{} is not a valid version!')
        self.__version = val

    def __repr__(self):
        return 'DomainConfig({})'.format(
            ', '.join(['{} = "{}"'.format(k, self.__getattribute__(k)) for k in
                       ["version", "ksk_frequency", "ksk_algo", "ksk_keysize", "ksk_method", "zsk_frequency",
                        "zsk_algo", "zsk_keysize", "zsk_method", "key_style"]]))
    def __str__(self):
        return(json_tricks.dumps({
            'version': self.version,
            'ksk_frequency': self.ksk_frequency,
            'ksk_algo': self.ksk_algo,
            'ksk_keysize': self.ksk_keysize,
            'ksk_method': self.ksk_method,
            'zsk_frequency': self.zsk_frequency,
            'zsk_algo': self.zsk_algo,
            'zsk_keysize': self.zsk_keysize,
            'zsk_method': self.zsk_method,
            'key_style': self.key_style,
        }))
