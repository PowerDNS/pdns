algo_to_shorthand = {
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

shorthand_to_algo = {v: k for k, v in algo_to_shorthand.items()}

algo_to_bits = {
    13: 256,
    14: 512,
    15: 32,
    16: 57.
}


class CryptoKey:
    """
    Represents a CryptoKey from the API
    """
    _algo = None

    def __init__(self, id, active, keytype, flags=None, algo=None, dnskey=None, ds=None, privatekey=None, **kwargs):
        """
        Construct a new CryptoKey

        :param int id: The id number of the key
        :param bool active: Whether or not this key is active
        :param string keytype: The type of key, KSK, ZSK or CSK
        :param int flags: The flags of this key
        :param algo: The algorithm of the key. Can be an integer or a string mnemonic
        :param string dnskey: The DNSKEY zonefile content
        :param list(string) ds: The DS records for this key
        :param string privatekey: The private key content
        :param dict kwargs: for compatibility with (future) API responses, ignored
        """
        self.id = id
        self.active = active
        self.keytype = keytype
        self.flags = flags
        self.dnskey = dnskey
        self.ds = ds
        self.privatekey = privatekey
        self.algo = algo or dnskey.split(' ')[2]

    def __repr__(self):
        return 'CryptoKey({id}, {active}, {keytype}, {flags}, {algo}, {dnskey}, {ds}, "{privatekey})'.format(
            id=self.id, active=self.active, keytype=self.keytype, flags=self.flags, algo=self.algo, dnskey=self.dnskey,
            ds=self.ds, privatekey=self.privatekey)

    def __str__(self):
        return str({
            'id': self.id,
            'active': self.active,
            'keytype': self.keytype,
            'flags': self.flags,
            'dnskey': self.dnskey,
            'ds': self.ds,
            'privatekey': self.privatekey,
            'algo': self.algo,
        })

    @property
    def algo(self):
        """
        Returns the algorithm of this key

        :return: Either the mnemonic or the algorithm number is the mnemonic is unknown
        """
        return algo_to_shorthand.get(self._algo, self._algo)

    @algo.setter
    def algo(self, val):
        if isinstance(val, int):
            self._algo = val
            return
        if isinstance(val, str):
            try:
                self._algo = int(val)
            except ValueError:
                self.algo = shorthand_to_algo.get(val, val)
            return
        raise ValueError("Value is not a str or int, but a {}".format(type(val)))

