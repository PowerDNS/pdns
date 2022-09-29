import yaml
import datetime
import logging

from pdnsapi.api import PDNSApi
import pdnskeyroller.keyrollerdomain

logger = logging.getLogger(__name__)


class KeyrollerConfig:
    def __init__(self, configfile):
        self._configfile = configfile
        self._config = self._load_config()

    def _load_config(self):
        # These are all the Defaults
        tmp_conf = {
            'keyroller': {
                'loglevel': 'info',
            },
            'API': {
                'version': 1,
                'baseurl': 'http://localhost:8081',
                'server': 'localhost',
                'apikey': '',
                'timeout': '2',
            },
            'domain_defaults': {
                'ksk_frequency': 0,
                'ksk_algo': 13,
                'ksk_method': 'prepublish',
                'zsk_frequency': '6w',
                'zsk_algo': 13,
                'zsk_method': 'prepublish',
                'key_style': 'single',
                'ksk_keysize': 3069,
                'zsk_keysize': 3069,
            },
        }

        logger.debug("Loading configuration from {}".format(self._configfile))
        try:
            with open(self._configfile, 'r') as f:
                a = yaml.safe_load(f)
                if a:
                    for k, v in tmp_conf.items():
                        if isinstance(v, dict) and isinstance(a.get(k), dict):
                            tmp_conf[k].update(a.get(k))
                        if isinstance(v, list) and isinstance(a.get(k), list):
                            tmp_conf[k] = a.get(k)

            loglevel = getattr(logging, tmp_conf['keyroller']['loglevel'].upper())
            if not isinstance(loglevel, int):
                loglevel = logging.INFO
            logger.info("Setting loglevel to {}".format(loglevel))
            logging.basicConfig(level=loglevel)

        except FileNotFoundError as e:
            logger.error('Unable to load configuration file: {}'.format(e))

        return tmp_conf

    def api(self):
        return self._config['API']

    def defaults(self):
        return self._config['domain_defaults']
