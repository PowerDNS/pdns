#!/usr/bin/env python3
import argparse
import logging
import sys
from pdnskeyroller import domainstate, domainconfig, keyrollerdomain
from pdnskeyroller.config import KeyrollerConfig
from pdnskeyroller.prepublishkeyroll import PrePublishKeyRoll
from pdnsapi.api import PDNSApi
from datetime import datetime, timedelta
import random

logger = logging.getLogger('pdns-keyroller')

def display_keyrollerdomain_infos(zone, api):
    zoneconf = keyrollerdomain.KeyrollerDomain(zone, api)
    if zoneconf.state :
        if zoneconf.state.is_rolling:
            timeleft = zoneconf.state.current_roll.current_step_datetime - datetime.now()
            logger.info(
                '{} is rolling its {} using the {} method. It is in the step {}, which was made {}. Next step scheduled {}'.format(
                    zone, zoneconf.state.current_roll.keytype.upper(),
                    zoneconf.state.current_roll.rolltype, zoneconf.state.current_roll.current_step_name,
                    zoneconf.state.current_roll.step_datetimes[-1],
                    "in {}".format(timeleft) if timeleft > timedelta(0) else "ASAP"
                )
            )
        else:
            logger.info('{} is not rolling. Last KSK roll was {} and the last ZSK roll was {}'.format(
                zone, zoneconf.state.last_ksk_roll_str, zoneconf.state.last_zsk_roll_str))
    else :
        logger.info('{} is not rolling'.format(zone))

if __name__ == '__main__':
    argp = argparse.ArgumentParser(
        prog='pdns-keyroller-ctl', formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='PowerDNS DNSSEC key-roller')
    argp.add_argument('--config', '-c', metavar='PATH', type=str, default='/etc/powerdns/pdns-keyroller.conf',
                      help='Load this configuration file')
    argp.add_argument('--baseurl', '-b', required=False, metavar='BASEURL', help='The base-URL for the authoritative webserver'
                      'Overrides the one set in the config-file')
    argp.add_argument('--apikey', '-k', required=False, metavar='API-KEY', help='The key needed to access the API')
    argp.add_argument('--verbose', '-v', action='count', help='Be more verbose')
    argp.set_defaults(command='none')

    sub_parsers = argp.add_subparsers()

    configs_parser = sub_parsers.add_parser('configs', help='Lists configured domains')
    configs_parser.set_defaults(command='configs', action='list')

    configs_subparsers = configs_parser.add_subparsers()

    configs_show_parser = configs_subparsers.add_parser('show', help='Show the roll configuration of the current domain')
    configs_show_parser.set_defaults(action='show')
    configs_show_parser.add_argument('domain', metavar='DOMAIN')

    configs_roll_parser = configs_subparsers.add_parser('roll', help='Setup the domain for autoroll')
    configs_roll_parser.set_defaults(action='roll')
    configs_roll_parser.add_argument('domain', metavar='DOMAIN')

    configs_roll_parser.add_argument('--force', '-f', required=False, default=False, action="store_true", help='Force creation even if a configuration already exists')
    configs_roll_parser.add_argument('--ksk-frequency', required=False)
    configs_roll_parser.add_argument('--ksk-algo', required=False)
    configs_roll_parser.add_argument('--zsk-algo', required=False)
    configs_roll_parser.add_argument('--zsk-frequency', required=False)

    configs_list_parser = configs_subparsers.add_parser('list', help='List all configured domains')
    configs_list_parser.set_defaults(action='list')



    # roll
    roll_parser = sub_parsers.add_parser('roll', help='Manipulate current rolls')
    roll_parser.set_defaults(command='roll', action='waiting')

    roll_subparsers = roll_parser.add_subparsers()

    roll_waiting_parser = roll_subparsers.add_parser('waiting', help='List waiting zones (KSK rolls waiting for DS change)')
    roll_waiting_parser.set_defaults(action='waiting')

    roll_step_parser = roll_subparsers.add_parser('step', help='Step waiting roll')
    roll_step_parser.set_defaults(action='step')

    roll_step_parser.add_argument('domain', metavar='DOMAIN')
    roll_step_parser.add_argument('ttl', metavar='TTL')

    arguments = argp.parse_args()

    if arguments.verbose:
        if arguments.verbose == 1:
            logging.basicConfig(level=logging.INFO)
        else:
            logging.basicConfig(level=logging.DEBUG)

    config = KeyrollerConfig(arguments.config)
    api_config = config.api()
    try:
        if arguments.baseurl:
            api_config['baseurl'] = arguments.baseurl
        if arguments.apikey:
            api_config['apikey'] = arguments.apikey
        api = PDNSApi(**api_config)
    except ConnectionError as e:
        logger.error("Unable to connect to PowerDNS: {}".format(e))
        sys.exit(1)

    if arguments.command == 'none':
        argp.print_help()
        sys.exit(1)

    if arguments.command == 'configs':
        if arguments.action == 'list':
            for zone in api.get_zones():
                try:
                    display_keyrollerdomain_infos(zone.id, api)
                except FileNotFoundError:
                    logger.debug("No config found for domain {}".format(zone.id))
                    continue
                except Exception as e:
                    logger.error("Unable to get config for domain {}: {}".format(zone.id, e))
        if arguments.action == 'show':
            try:
                domaincfg = domainconfig.from_api(arguments.domain, api)
                logger.info(
                    '{} has the following roll configuration: KSK {}, ZSK {}'.format(
                        arguments.domain,
                        domaincfg.ksk_frequency,
                        domaincfg.zsk_frequency,
                    )
                )
                display_keyrollerdomain_infos(arguments.domain, api)
            except FileNotFoundError:
                logger.error("{} is not under automatic keyroll".format(arguments.domain))
            except ConnectionError:
                logger.error(
                    'No such domain {}'.format(
                        arguments.domain
                    )
                )
            except Exception as e:
                logger.error("Unable to get config for domain {}: {}".format(zone.id, e))


        if arguments.action == 'roll':
            docreate = False
            try:
                domaincfg = domainconfig.from_api(arguments.domain, api)
                if not arguments.force:
                    logger.error(
                        '{} already has an autoroll setup'.format(
                            arguments.domain
                        )
                    )
                else:
                    docreate = True
            except FileNotFoundError:
                docreate = True
            except ConnectionError:
                logger.error(
                    'No such domain {}'.format(
                        arguments.domain
                    )
                )

            if docreate:
                domaincfg = domainconfig.DomainConfig(**config.defaults())
                try:
                    if arguments.ksk_frequency:
                        domaincfg.ksk_frequency = arguments.ksk_frequency
                    if arguments.ksk_algo:
                        domaincfg.ksk_algo = arguments.ksk_algo
                    if arguments.zsk_frequency:
                        domaincfg.zsk_frequency = arguments.zsk_frequency
                    if arguments.zsk_algo:
                        domaincfg.zsk_algo = arguments.zsk_algo
                    domainconfig.to_api(arguments.domain, api, domaincfg)
                    logger.info(
                        'Successfully created configuration for {}: KSK {}, ZSK {}'.format(
                            arguments.domain,
                            domaincfg.ksk_frequency,
                            domaincfg.zsk_frequency,
                        )
                    )
                except SyntaxError as e:
                    logger.error(
                        'Unable to setup given frequency {}: {}'.format(
                            arguments.domain, e
                        )
                    )
    if arguments.command == 'roll':
        if arguments.action == 'waiting':
            for zone in api.get_zones():
                try:
                    zoneconf = keyrollerdomain.KeyrollerDomain(zone.id, api)
                    if zoneconf.state and zoneconf.state.is_rolling and zoneconf.state.current_roll.is_waiting_ds():
                        logger.info('{} is waiting for DS replacement'.format(zone.id))
                except FileNotFoundError:
                    continue
        elif arguments.action == 'step':
            try:
                zoneconf = keyrollerdomain.KeyrollerDomain(arguments.domain, api)
                if zoneconf.state and zoneconf.state.current_roll.is_waiting_ds():
                    zoneconf.step(force=True, customttl=int(arguments.ttl))
                    logger.info(
                        'Successfuly steped {}, now waiting {} before deleting the keys'.format(
                            arguments.domain,
                            arguments.ttl,
                        )
                    )

            except FileNotFoundError:
                logger.error(
                    'No such zone to step {}'.format(
                        arguments.domain
                    )
                )
