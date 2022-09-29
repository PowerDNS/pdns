class RRSet:
    def __init__(self, name, type, ttl, records, comments=[]):
        """
        Represents and RRSet from the API, see https://doc.powerdns.com/md/httpapi/api_spec/#zone95collection

        :param str name: Name of the rrset
        :param str type: Type of the rrset
        :param int ttl: Time to Live of the rrset
        :param list records: a list of :class:`Record`
        :param list comments: a list of :class:`Comment`
        """
        self._records = []
        self._comments = []
        self.name = name
        self.rtype = type
        self.ttl = ttl
        self.records = records
        self.comments = comments

    def __repr__(self):
        return 'RRSet("{}", "{}", {}, {}, {})'.format(self.name, self.rtype, self.ttl, self.records, self.comments)

    def __str__(self):
        ret = '\n'.join(['; {}'.format(c) for c in self.comments])
        ret += '\n'.join(['{}{}\tIN\t{}\t{}'.format(';' if rec.disabled else '', self.name, self.rtype, rec.content)
                         for rec in self.records])
        return ret

    @property
    def records(self):
        return self._records

    @records.setter
    def records(self, val):
        if not isinstance(val, list):
            raise Exception('TODO')
        if all(isinstance(v, dict) for v in val):
            self._records = []
            for v in val:
                self._records.append(Record(**v))
            return
        if not all(isinstance(v, Record) for v in val):
            raise Exception('Not all records are of type Record')
        self._records = val

    @property
    def comments(self):
        return self._comments

    @comments.setter
    def comments(self, val):
        if not isinstance(val, list):
            raise Exception('TODO')
        if all(isinstance(v, dict) for v in val):
            self._comments = []
            for v in val:
                self._comments.append(Comment(**v))
            return
        if not all(isinstance(v, Comment) for v in val):
            raise Exception('Not all comments are of type Comment')
        self._comments = val


class Record:
    def __init__(self, content, disabled):
        """
        Represents a Record from the API. Note that is does not contian the rrname nor ttl (these are held by the
        encompassing :class:`RRSet` object).

        :param str content: The content of the record in zonefile-format
        :param bool disabled: True if this record is disabled
        """
        self.content = content
        self.disabled = bool(disabled)

    def __repr__(self):
        return 'Record("{}", "{}")'.format(self.content, self.disabled)


class Comment:
    def __init__(self, content, modified_at, account):
        """
        Constructor, see https://doc.powerdns.com/md/httpapi/api_spec/#zone95collection

        :param str content: The content of the comment
        :param int modified_at: A timestamp when the comment was changed
        :param account: The account that made this comment
        """
        self.content = content
        # TODO make modified_at a datetime.datetime
        self.modified_at = modified_at
        self.account = account

    def __repr__(self):
        return 'Comment("{}", "{}", "{})'.format(self.content, self.modified_at, self.account)

    def __str__(self):
        return '{} by {} on {}'.format(self.content, self.account, self.modified_at)


class Zone:
    """
    This represents a Zone-object
    """
    _keys = ["id", "name", "url", "kind", "serial", "notified_serial", "masters", "dnssec", "nsec3param",
             "nsec3narrow", "presigned", "soa_edit", "soa_edit_api", "account", "nameservers", "servers",
             "recursion_desired", "rrsets", "last_check"]
    _rrsets = []
    _kind = ''

    def __init__(self, **kwargs):
        """
        Constructor
        :param kwargs: Any of the elements named in https://doc.powerdns.com/md/httpapi/api_spec/#zone95collection
        """
        for k, v in kwargs.items():
            if k in Zone._keys:
                setattr(self, k, v)

    def __str__(self):
        ret = "{}".format('\n'.join(['; {} = {}'.format(
            k, str(getattr(self, k))) for k in Zone._keys if getattr(self, k, None) and k != 'rrsets']))
        ret += "\n{}".format('\n'.join([str(v) for v in self.rrsets]))
        return ret

    def __repr__(self):
        return 'Zone({})'.format(
            ', '.join(['{}="{}"'.format(k, getattr(self, k)) for k in Zone._keys if getattr(self, k, None)]))

    @property
    def kind(self):
        return self._kind

    @kind.setter
    def kind(self, val):
        if val not in ['Native', 'Master', 'Slave']:
            raise Exception("TODO")
        self._kind = val

    @property
    def rrsets(self):
        return self._rrsets

    @rrsets.setter
    def rrsets(self, val):
        """
        Sets the :class:`RRSet`s for this Zone
        :param val: a list of :class:`RRSet`s or :class:`dict`s. The latter is converted to RRsets
        :return:
        """
        if not isinstance(val, list):
            raise Exception('Please pass a list of RRSets')
        if all(isinstance(v, dict) for v in val):
            self._rrsets = []
            for v in val:
                self._rrsets.append(RRSet(**v))
            return
        if not all(isinstance(v, RRSet) for v in val):
            raise Exception('Not all rrsets are actually RRSets')
        self._rrsets = val
