import requests
from authtests import AuthTest

class TestBasic(AuthTest):
    _config_template = """
    launch = {backend}
    webserver = yes
    webserver-address = 127.0.0.1
    webserver-port = 8053
    webserver-allow-from = 127.0.0.1
    """

    @classmethod
    def setUpClass(cls):
        super(TestBasic, cls).setUpClass()

    def test_basic(self):
        r = requests.get('http://127.0.0.1:8053')
        self.assertEqual(r.status_code, 200)

class TestDualStack(AuthTest):
    _config_template = """
    launch = {backend}
    webserver = yes
    webserver-address = [::]
    webserver-port = 8053
    webserver-allow-from = 127.0.0.1
    """

    @classmethod
    def setUpClass(cls):
        super(TestDualStack, cls).setUpClass()

    def test_ds(self):
        r = requests.get('http://127.0.0.1:8053')
        self.assertEqual(r.status_code, 200)

class TestDualStackBackwardsCompat(AuthTest):
    _config_template = """
    launch = {backend}
    webserver = yes
    webserver-address = [::]
    webserver-port = 8053
    webserver-allow-from = ::ffff:127.0.0.1
    """

    def test_ds_compat(self):
        r = requests.get('http://127.0.0.1:8053')
        self.assertEqual(r.status_code, 200)

class TestUnauthorized(AuthTest):
    _config_template = """
    launch = {backend}
    webserver = yes
    webserver-address = 127.0.0.1
    webserver-port = 8053
    webserver-allow-from = 224.0.0.0
    """

    def test_unauthorized(self):
        try:
            requests.get('http://127.0.0.1:8053')
            self.fail()
        except requests.exceptions.ConnectionError:
            pass

class TestUnauthorizedDualStack(AuthTest):
    _config_template = """
    launch = {backend}
    webserver = yes
    webserver-address = [::]
    webserver-port = 8053
    webserver-allow-from = 224.0.0.0
    """

    def test_unauthorized(self):
        try:
            requests.get('http://127.0.0.1:8053')
            self.fail()
        except requests.exceptions.ConnectionError:
            pass

