#!/usr/bin/env python
from dnsdisttests import DNSDistTest, pickAvailablePort

class TestStructuredLoggingDefaultBackendFromYaml(DNSDistTest):

    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

logging:
  structured:
    enabled: true
"""
    _dnsDistPort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _yaml_config_params = ['_dnsDistPort', '_testServerPort']
    _config_params = []
    _checkConfigExpectedOutput = None
    _checkConfigExpectedOutputPrefix = b'msg="Configuration OK" subsystem="setup"'

    def testOK(self):
        pass

class TestStructuredLoggingJSONBackendFromYaml(DNSDistTest):

    _yaml_config_template = """---
binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

logging:
  structured:
    enabled: true
    backend: "json"
"""
    _dnsDistPort = pickAvailablePort()
    _testServerPort = pickAvailablePort()
    _yaml_config_params = ['_dnsDistPort', '_testServerPort']
    _config_params = []
    _checkConfigExpectedOutput = None
    _checkConfigExpectedOutputPrefix = b'{"level": "0", "msg": "Configuration OK", "path":'

    def testOK(self):
        pass

class TestStructuredLoggingDefaultBackendFromLua(DNSDistTest):

    _config_template = """
setStructuredLogging(true)

newServer{address="127.0.0.1:%d"}
"""
    _testServerPort = pickAvailablePort()
    _checkConfigExpectedOutput = None
    _checkConfigExpectedOutputPrefix = b'msg="Configuration OK" subsystem="setup"'

    def testOK(self):
        pass

class TestStructuredLoggingJSONBackendFromLua(DNSDistTest):

    _config_template = """
setStructuredLogging(true, {backend="json"})

newServer{address="127.0.0.1:%d"}
"""
    _testServerPort = pickAvailablePort()
    _checkConfigExpectedOutput = None
    _checkConfigExpectedOutputPrefix = b'{"level": "0", "msg": "Configuration OK", "path":'

    def testOK(self):
        pass


class TestStructuredLoggingDefaultBackendWithInstanceFromYaml(
    TestStructuredLoggingDefaultBackendFromYaml
):
    _yaml_config_template = """---
general:
  server_id: "foobar"

binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

logging:
  structured:
    enabled: true
    set_instance_from_server_id: true
"""
    _checkConfigExpectedOutputPrefix = b'msg="Configuration OK" subsystem="setup"'


class TestStructuredLoggingJSONBackendWithInstanceFromYaml(
    TestStructuredLoggingJSONBackendFromYaml
):
    _yaml_config_template = """---
general:
  server_id: "foobar"

binds:
  - listen_address: "127.0.0.1:%d"
    protocol: Do53

backends:
  - address: "127.0.0.1:%d"
    protocol: Do53

logging:
  structured:
    enabled: true
    backend: "json"
    set_instance_from_server_id: true
"""
    _checkConfigExpectedOutputPrefix = (
        b'{"instance": "foobar", "level": "0", "msg": "Configuration OK", "path":'
    )


class TestStructuredLoggingDefaultBackendWithInstanceFromLua(
    TestStructuredLoggingDefaultBackendFromLua
):
    _config_template = """
setServerID("foobar")
setStructuredLogging(true, {setInstanceFromServerID=true})

newServer{address="127.0.0.1:%d"}
"""
    _checkConfigExpectedOutputPrefix = b'msg="Configuration OK" subsystem="setup" level="0" prio="Info" instance="foobar" ts='


class TestStructuredLoggingJSONBackendWithInstanceFromLua(
    TestStructuredLoggingJSONBackendFromLua
):

    _config_template = """
setServerID("foobar")
setStructuredLogging(true, {backend="json", setInstanceFromServerID=true})

newServer{address="127.0.0.1:%d"}
"""
    _checkConfigExpectedOutputPrefix = (
        b'{"instance": "foobar", "level": "0", "msg": "Configuration OK", "path":'
    )
