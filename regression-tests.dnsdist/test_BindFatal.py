#!/usr/bin/env python
import unittest

from dnsdisttests import DNSDistTest

_NON_EXISTING_ADDR = "192.0.2.1"  # RFC 5737 TEST-NET, never locally routable


class _BindFatalMixin:
    """Mixin: allow dnsdist to exit during startup (bind_fatal=true)."""

    _config_params = []
    _startupFailed = False

    @classmethod
    def setUpClass(cls):
        cls._startupFailed = False
        try:
            super().setUpClass()
        except unittest.SkipTest:
            raise
        except Exception:
            cls._startupFailed = True

    @classmethod
    def tearDownClass(cls):
        for backgroundThread in cls._backgroundThreads:
            cls._backgroundThreads[backgroundThread] = False
        if hasattr(cls, "_sock"):
            cls._sock.close()
        if cls._dnsdist is not None:
            cls.killProcess(cls._dnsdist)


# Lua – webserver


class TestWebserverBindFatalNotSet(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Succeeds to start when webserver bind fails using Lua configuration, because the default value of bind_fatal is false.
    """

    _config_params = []
    _config_template = (
        """
    webserver("%s:80")
    """
        % _NON_EXISTING_ADDR
    )

    def testStartedSuccessfully(self):
        self.assertIsNone(self._dnsdist.poll(), "dnsdist should still be running")


class TestWebserverBindFatalFalse(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Succeeds to start when webserver bind fails using Lua configuration, because bind_fatal is explicitly set to false.
    """

    _config_params = []
    _config_template = (
        """
    setWebserverBindFatal(false)
    webserver("%s:80")
    """
        % _NON_EXISTING_ADDR
    )

    def testStartedSuccessfully(self):
        self.assertIsNone(self._dnsdist.poll(), "dnsdist should still be running")


class TestWebserverBindFatalTrue(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Fails to start when webserver bind fails using Lua configuration, because bind_fatal is explicitly set to true.
    """

    _config_template = (
        """
    setWebserverBindFatal(true)
    webserver("%s:80")
    """
        % _NON_EXISTING_ADDR
    )

    def testExitedOnStartup(self):
        self.assertTrue(self._startupFailed, "dnsdist should have failed to start but did not")


# YAML – webserver


class TestYamlWebserverBindFatalNotSet(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Succeeds to start when webserver bind fails using YAML configuration, because the default value of bind_fatal is false.
    """

    _yaml_config_template = (
        """---
webserver:
  listen_addresses:
    - "%s:80"
"""
        % _NON_EXISTING_ADDR
    )

    def testStartedSuccessfully(self):
        self.assertIsNone(self._dnsdist.poll(), "dnsdist should still be running")


class TestYamlWebserverBindFatalFalse(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Succeeds to start when webserver bind fails using YAML configuration, because bind_fatal is explicitly set to false.
    """

    _yaml_config_template = (
        """---
webserver:
  listen_addresses:
    - "%s:80"
  bind_fatal: false
"""
        % _NON_EXISTING_ADDR
    )

    def testStartedSuccessfully(self):
        self.assertIsNone(self._dnsdist.poll(), "dnsdist should still be running")


class TestYamlWebserverBindFatalTrue(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Fails to start when webserver bind fails using YAML configuration, because bind_fatal is explicitly set to true.
    """

    _yaml_config_template = (
        """---
webserver:
  listen_addresses:
    - "%s:80"
  bind_fatal: true
"""
        % _NON_EXISTING_ADDR
    )

    def testExitedOnStartup(self):
        self.assertTrue(self._startupFailed, "dnsdist should have failed to start but did not")


# Lua – control socket


class TestConsoleBindFatalNotSet(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Succeeds to start when control socket bind fails using Lua configuration, because the default value of bind_fatal is false.
    """

    _config_template = (
        """
    controlSocket("%s:5199")
    """
        % _NON_EXISTING_ADDR
    )

    def testStartedSuccessfully(self):
        self.assertIsNone(self._dnsdist.poll(), "dnsdist should still be running")


class TestConsoleBindFatalFalse(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Succeeds to start when control socket bind fails using Lua configuration, because bind_fatal is explicitly set to false.
    """

    _config_template = (
        """
    setConsoleBindFatal(false)
    controlSocket("%s:5199")
    """
        % _NON_EXISTING_ADDR
    )

    def testStartedSuccessfully(self):
        self.assertIsNone(self._dnsdist.poll(), "dnsdist should still be running")


class TestConsoleBindFatalTrue(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Fails to start when control socket bind fails using Lua configuration, because bind_fatal is explicitly set to true.
    """

    _config_template = (
        """
    setConsoleBindFatal(true)
    controlSocket("%s:5199")
    """
        % _NON_EXISTING_ADDR
    )

    def testExitedOnStartup(self):
        self.assertTrue(self._startupFailed, "dnsdist should have failed to start but did not")


# YAML – control socket


class TestYamlConsoleBindFatalNotSet(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Succeeds to start when control socket bind fails using YAML configuration, because the default value of bind_fatal is false.
    """

    _yaml_config_template = (
        """---
console:
  listen_address: "%s:5199"
"""
        % _NON_EXISTING_ADDR
    )

    def testStartedSuccessfully(self):
        self.assertIsNone(self._dnsdist.poll(), "dnsdist should still be running")


class TestYamlConsoleBindFatalFalse(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Succeeds to start when control socket bind fails using YAML configuration, because bind_fatal is explicitly set to false.
    """

    _yaml_config_template = (
        """---
console:
  listen_address: "%s:5199"
  bind_fatal: false
"""
        % _NON_EXISTING_ADDR
    )

    def testStartedSuccessfully(self):
        self.assertIsNone(self._dnsdist.poll(), "dnsdist should still be running")


class TestYamlConsoleBindFatalTrue(_BindFatalMixin, DNSDistTest):
    """
    BindFatal: Fails to start when control socket bind fails using YAML configuration, because bind_fatal is explicitly set to true.
    """

    _yaml_config_template = (
        """---
console:
  listen_address: "%s:5199"
  bind_fatal: true
"""
        % _NON_EXISTING_ADDR
    )

    def testExitedOnStartup(self):
        self.assertTrue(self._startupFailed, "dnsdist should have failed to start but did not")
