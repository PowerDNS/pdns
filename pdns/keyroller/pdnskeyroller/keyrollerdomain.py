from pdnsapi.api import PDNSApi
import logging
import pdnskeyroller.domainconfig
import pdnskeyroller.domainstate
from pytimeparse.timeparse import timeparse
import datetime

logger = logging.getLogger(__name__)


class KeyrollerDomain:
    def __init__(self, zone, api, config=None, state=None):
        if not isinstance(api, PDNSApi):
            raise Exception("api is not a PDNSApi")

        self.zone = zone
        self.api = api
        if not config:
            config = pdnskeyroller.domainconfig.from_api(zone, api)

        if not isinstance(config, pdnskeyroller.domainconfig.DomainConfig):
            raise Exception("config is not a DomainConfig")

        self.config = config

        if not state:
            state = pdnskeyroller.domainstate.from_api(zone, api)

        if not isinstance(state, pdnskeyroller.domainstate.DomainState):
            raise Exception("state is not a DomainState")

        self.state = state

    def next_ksk_roll(self):
        if not self.state.is_rolling:
            if self.config.ksk_frequency != 0:
                return self.state.last_roll_date("ksk") + datetime.timedelta(
                    seconds=timeparse(self.config.ksk_frequency)
                )
        return None

    def next_zsk_roll(self):
        if not self.state.is_rolling:
            if self.config.zsk_frequency != 0:
                return self.state.last_roll_date("zsk") + datetime.timedelta(
                    seconds=timeparse(self.config.zsk_frequency)
                )
        return None

    @property
    def current_step_name(self):
        if not self.state.is_rolling:
            return None
        return self.state.current_roll.current_step_name

    def step(self, force=False, customttl=0):
        if not self.state.is_rolling:
            return
        self.state.current_roll.step(self.zone, self.api, force, customttl)
        pdnskeyroller.domainstate.to_api(self.zone, self.api, self.state)

    @property
    def next_action_datetime(self):
        """
        The datetime for the next roll or action

        :return:
        """
        ret = []
        if self.state.is_rolling:
            nextaction = self.state.current_roll.current_step_datetime
            ret.append(nextaction)
            logger.debug("{}: Next roll step {}".format(self.zone, nextaction))
        else:
            if self.config.zsk_frequency != 0:
                nextaction = self.next_zsk_roll()
                ret.append(nextaction)
                logger.debug("{}: Next ZSK roll {}".format(self.zone, nextaction))
            if self.config.ksk_frequency != 0:
                nextaction = self.next_ksk_roll()
                ret.append(nextaction)
                logger.debug("{}: Next KSK roll {}".format(self.zone, nextaction))
        if ret:
            ret.sort()
            return ret[0]
        return None

    def __repr__(self):
        return 'keyrollerDomain("{}", {}, {}, {})'.format(self.zone, self.api, self.config, self.state)
