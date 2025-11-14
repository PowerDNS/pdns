import logging
import pdnsapi.api
from datetime import datetime
import json_tricks.nonp as json_tricks
from pdnskeyroller import PDNSKEYROLLER_STATE_metadata_kind
from pdnskeyroller.keyroll import KeyRoll
from pdnskeyroller.prepublishkeyroll import PrePublishKeyRoll

DOMAINSTATE_VERSION = 1
logger = logging.getLogger(__name__)


def from_api(zone, api):
    """
    Get the keyroller state from the API

    :param string zone: The zone to het the state for
    :param pdnsapi.api.PDNSApi api: the API endpoint to use
    :return: The state for ``zone``
    :rtype: DomainState
    :raises: ValueError if the JSON from the domain metadata cannot be unpacked
    """
    if not isinstance(api, pdnsapi.api.PDNSApi):
        raise Exception("api must be a PDNSApi instance, not a {}".format(type(api)))
    tmp_state = api.get_zone_metadata(zone, PDNSKEYROLLER_STATE_metadata_kind).metadata

    if not tmp_state:
        return DomainState()

    if len(tmp_state) > 1:
        raise Exception("More than one {} metadata found!".format(PDNSKEYROLLER_STATE_metadata_kind))

    try:
        state = json_tricks.loads(tmp_state[0])
    except Exception as e:
        raise ValueError(e)

    return DomainState(**state)


def to_api(zone, api, state):
    """

    :param zone:
    :param api:
    :param state:
    :return:
    """
    if not isinstance(api, pdnsapi.api.PDNSApi):
        raise Exception("api must be a PDNSApi instance, not a {}".format(type(api)))
    if not isinstance(state, DomainState):
        raise Exception("state must be a DomainState instance, not a {}".format(type(state)))

    if state.current_roll.complete:
        state.set_last_roll_date(state.current_roll.keytype, state.current_roll.step_datetimes[-1])
        state.current_roll = KeyRoll()

    api.set_zone_metadata(zone, PDNSKEYROLLER_STATE_metadata_kind, str(state))


class DomainState:
    __last_zsk_roll_datetime = None
    __last_ksk_roll_datetime = None
    __current_roll = None
    __version = DOMAINSTATE_VERSION

    def __init__(
        self,
        version=DOMAINSTATE_VERSION,
        last_ksk_roll_datetime=datetime.min,
        last_zsk_roll_datetime=datetime.min,
        current_roll=KeyRoll(),
        **kwargs,
    ):
        self.version = version
        self.last_ksk_roll_datetime = (
            last_ksk_roll_datetime
            if isinstance(last_ksk_roll_datetime, datetime)
            else datetime.fromtimestamp(last_ksk_roll_datetime)
        )
        self.last_zsk_roll_datetime = (
            last_zsk_roll_datetime
            if isinstance(last_zsk_roll_datetime, datetime)
            else datetime.fromtimestamp(last_zsk_roll_datetime)
        )
        self.current_roll = current_roll
        if kwargs:
            logger.warning("Unknown keys passed: {}".format(", ".join([k for k, v in kwargs.items()])))

    @property
    def last_zsk_roll_datetime(self):
        return self.__last_zsk_roll_datetime

    @last_zsk_roll_datetime.setter
    def last_zsk_roll_datetime(self, val):
        if not isinstance(val, datetime):
            raise Exception("Can not set last_zsk_roll_datetime: not a datetime object")
        self.__last_zsk_roll_datetime = val

    @property
    def last_ksk_roll_datetime(self):
        return self.__last_ksk_roll_datetime

    @last_ksk_roll_datetime.setter
    def last_ksk_roll_datetime(self, val):
        if not isinstance(val, datetime):
            raise Exception("Can not set last_ksk_roll_datetime: not a datetime object")
        self.__last_ksk_roll_datetime = val

    @property
    def last_ksk_roll_str(self):
        return "never" if self.last_ksk_roll_datetime == datetime.min else str(self.last_ksk_roll_datetime)

    @property
    def last_zsk_roll_str(self):
        return "never" if self.last_zsk_roll_datetime == datetime.min else str(self.last_zsk_roll_datetime)

    @property
    def current_roll(self):
        return self.__current_roll

    @current_roll.setter
    def current_roll(self, val):
        if not isinstance(val, (KeyRoll, PrePublishKeyRoll)):
            raise Exception("Roll is not a KeyRoll")
        self.__current_roll = val

    @property
    def version(self):
        return self.__version

    @version.setter
    def version(self, val):
        if val != 1:
            raise Exception("{} is not a valid version!")
        self.__version = val

    def __repr__(self):
        return "DomainState({})".format(
            ", ".join(
                [
                    "{}={}".format(k, v)
                    for k, v in [
                        ("version", self.version),
                        (
                            "last_ksk_roll_datetime",
                            self.last_ksk_roll_datetime.timestamp()
                            if self.last_ksk_roll_datetime > datetime.fromtimestamp(0)
                            else 0,
                        ),
                        (
                            "last_zsk_roll_datetime",
                            self.last_zsk_roll_datetime.timestamp()
                            if self.last_zsk_roll_datetime > datetime.fromtimestamp(0)
                            else 0,
                        ),
                        ("current_roll", self.current_roll),
                    ]
                ]
            )
        )

    def __str__(self):
        return json_tricks.dumps(
            {
                "version": self.version,
                "last_ksk_roll_datetime": self.last_ksk_roll_datetime.timestamp()
                if self.last_ksk_roll_datetime > datetime.fromtimestamp(0)
                else 0,
                "last_zsk_roll_datetime": self.last_zsk_roll_datetime.timestamp()
                if self.last_zsk_roll_datetime > datetime.fromtimestamp(0)
                else 0,
                "current_roll": self.current_roll,
            }
        )

    def set_last_roll_date(self, keytype, date):
        self.__setattr__("last_{}_roll_datetime".format(keytype), date)

    def last_roll_date(self, keytype):
        return self.__getattribute__("last_{}_roll_datetime".format(keytype))

    @property
    def is_rolling(self):
        return bool(not self.current_roll.complete and self.current_roll.started)
