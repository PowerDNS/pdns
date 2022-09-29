import pdnsapi.api
import json_tricks.nonp as json_tricks
from pdnskeyroller.util import (get_keys_of_type, DNSKEY_ALGO_TO_MNEMONIC, DNSKEY_MNEMONIC_TO_ALGO, validate_api)
from datetime import datetime, timedelta
from pdnskeyroller.keyroll import KeyRoll

_step_to_name = {
    0: 'initial',
    1: 'new DNSKEY',
    2: 'new DS/new RRSIGs',
    3: 'DNSKEY removal',
}


class PrePublishKeyRoll(KeyRoll):
    def __init__(self, **kwargs):
        super().__init__(rolltype='prepublish')
        self.current_step = kwargs.get('current_step', 0)
        self.complete = kwargs.get('complete', False)
        self.step_datetimes = list(map(lambda x: datetime.fromtimestamp(x), kwargs.get('step_datetimes', [])))
        self.current_step_datetime = datetime.fromtimestamp(kwargs.get('current_step_datetime', datetime.now().timestamp()))
        self.keytype = kwargs.get('keytype')
        self.algo = kwargs.get('algo')
        self.old_keyids = kwargs.get('old_keyids')
        self.new_keyid = kwargs.get('new_keyid')

    def initiate(self, zone, api, keytype, algo, bits=None, published=True):
        """
        Initiate a pre-publish rollover (:rfc:`RFC 6781 §4.1.1.1 <6781#section-4.1.1.1>`) for the ``keytype`` key of algorithm
    ``algo`` for ``zone``.

        The roll will **only** be initiated if there exists a ``keytype`` key of algorithm ``algo`` for the domain ``zone``.

        :param string zone: The zone to roll for
        :param pdnsapi.api.PDNSApi api: The API endpoint to use
        :param string keytype: The keytype to roll, must be one of 'ksk', 'zsk' or 'csk'
        :param string algo: The algorithm to roll the ``keytype`` for
        :param int bits: If needed, use this many bits for the new key for ``algo``
        """
        if self.started:
            raise Exception('Already rolling the {} for {}'.format(
                self.keytype, zone))
        validate_api(api)

        keytype = keytype.lower()
        if keytype not in ('ksk', 'zsk'):
            raise Exception('Invalid key type: {}'.format(keytype))

        current_keys = get_keys_of_type(zone, api, keytype)
        algo = DNSKEY_ALGO_TO_MNEMONIC.get(algo, algo)
        if not current_keys:
            raise Exception('There are no keys of type {} in zone {}, cannot roll!'.format(keytype, zone))
        if not any([k.algo == algo and k.keytype == keytype for k in current_keys]):
            raise Exception('No keys for algorithm {} in zone {}, cannot roll!'.format(algo, zone))

        active = True
        published = True
        if keytype == "zsk":
            active = False
        new_key = api.add_cryptokey(zone, keytype, active=active, algo=algo, bits=bits, published=published)
        self.current_step = 1
        self.complete = False
        self.step_datetimes = [datetime.now()]
        self.keytype = keytype
        self.algo = algo
        self.old_keyids = [k.id for k in current_keys if k.algo == algo and k.keytype == keytype]
        self.new_keyid = new_key.id
        httl = self._get_highest_ttl(zone, api)
        self.current_step_datetime = datetime.now() + timedelta(seconds=httl)

        api.bump_soa(zone);

    def _get_highest_ttl(self, zone, api, zoneobject=None):
        if zoneobject is None:
            zoneobject = api.get_zone(zone)
        httl = 0
        for rrset in zoneobject.rrsets:
            httl = max(rrset.ttl, httl)

        return httl

    def is_waiting_ds(self):
        return self.started and self.keytype == "ksk" and self.current_step == 1

    def step(self, zone, api, force=False, customttl=0):
        """
        Perform the next step in the keyroll

        :param string zone: The zone we are rolling for
        :param pdnsapi.api.PDNSApi api: The API endpoint to use
        :raises: Exception when a sanity check fails
        """
        validate_api(api)
        if not self.validate(zone, api):
            raise Exception('Keys for zone {}  do not match keys initially found. Refusing to continue'.format(zone))

        if not self.started:
            raise Exception('Can not go to the next step in phase "{}", did you mean to call initialize()?'.format(
                self.current_step_name))

        # make sure we are passed the expected datetime
        if self.current_step_datetime > datetime.now():
            return

        if self.current_step == 1:
            if self.keytype == "zsk":
                # activate the new keys and deactivate the old ones
                api.set_cryptokey_active(zone, self.new_keyid, active=True)
                for keyid in self.old_keyids:
                    api.set_cryptokey_active(zone, keyid, active=False)

                api.bump_soa(zone);

                httl = self._get_highest_ttl(zone, api)
                self.current_step_datetime = datetime.now() + timedelta(seconds=httl)
                self.step_datetimes.append(datetime.now())
                self.current_step = 2

            elif self.keytype == "ksk":
                if force == True and isinstance(customttl, int):
                    self.current_step_datetime = datetime.now() + timedelta(seconds=customttl)
                    self.step_datetimes.append(datetime.now())
                    self.current_step = 3

        elif self.current_step == 2:
            if self.keytype == "zsk":
                # remove the old keys
                for keyid in self.old_keyids:
                    api.delete_cryptokey(zone, keyid)
                api.bump_soa(zone);
                # rollover is finished
                self.complete = True
                self.step_datetimes.append(datetime.now())


        elif self.current_step == 3:
            if self.keytype == "ksk":
                # remove the old keys
                for keyid in self.old_keyids:
                    api.delete_cryptokey(zone, keyid)
                api.bump_soa(zone);
                # rollover is finished
                self.complete = True
                self.step_datetimes.append(datetime.now())

        else:
            raise Exception("Unknown step number {}".format(self.current_step))

    def validate(self, zone, api):
        """
        Checks if the current keys in the zone matches what we have

        :param string zone: The zone to check in
        :param pdnsapi.api.PDNSApi api: The API endpoint to use
        :return: True if the keys in the zone indeed match, False otherwise
        :rtype: bool
        """
        validate_api(api)
        to_match = self.old_keyids.copy()
        to_match.append(self.new_keyid)
        return all([k.id in to_match for k in api.get_cryptokeys(zone)
                    if k.algo == self.algo and k.keytype == self.keytype])

    def __str__(self):
        return json_tricks.dumps({
            'rolltype': 'prepublish',
            'current_step': self.current_step,
            'complete': self.complete,
            'current_step_datetime': self.current_step_datetime.timestamp(),
            'step_datetimes': list(map(lambda d: d.timestamp(), self.step_datetimes)),
            'keytype': self.keytype,
            'algo': self.algo,
            'old_keyids': self.old_keyids,
            'new_keyid': self.new_keyid,
        })
    def __json_encode__(self):
        # should return primitive, serializable types like dict, list, int, string, float...
        return {
            'rolltype': 'prepublish',
            'current_step': self.current_step,
            'complete': self.complete,
            'current_step_datetime': self.current_step_datetime.timestamp(),
            'step_datetimes': list(map(lambda d: d.timestamp(), self.step_datetimes)),
            'keytype': self.keytype,
            'algo': self.algo,
            'old_keyids': self.old_keyids,
            'new_keyid': self.new_keyid,
        }

    def __json_decode__(self, **kwargs):
        super().__init__(rolltype='prepublish')
        self.current_step = kwargs.get('current_step', 0)
        self.complete = kwargs.get('complete', False)
        self.step_datetimes = list(map(lambda x: datetime.fromtimestamp(x), kwargs.get('step_datetimes', [])))
        self.current_step_datetime = datetime.fromtimestamp(kwargs.get('current_step_datetime', datetime.now().timestamp()))
        self.keytype = kwargs.get('keytype')
        self.algo = kwargs.get('algo')
        self.old_keyids = kwargs.get('old_keyids')
        self.new_keyid = kwargs.get('new_keyid')

    def __repr__(self):
        return 'PrePublishRoll({})'.format(
            ', '.join(['{}={}'.format(k, v) for k, v in [
                ('current_step', self.current_step),
                ('complete', self.complete),
                ('current_step_datetime', self.current_step_datetime.timestamp()),
                ('step_datetimes', list(map(lambda d: d.timestamp(), self.step_datetimes))),
                ('keytype', self.keytype),
                ('algo', self.algo),
                ('old_keyids', self.old_keyids),
                ('new_keyid', self.new_keyid),
            ]]))

    @property
    def started(self):
        return self.current_step > 0

    @property
    def current_step_name(self):
        return _step_to_name.get(self.current_step)
