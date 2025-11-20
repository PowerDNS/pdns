from basicDNSSEC import BasicDNSSEC

class basicNSECTest(BasicDNSSEC):
    __test__ = True
    _confdir = 'basicNSEC'
    _auth_zones = BasicDNSSEC._auth_zones
