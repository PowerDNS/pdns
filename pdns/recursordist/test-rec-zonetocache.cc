#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

#include <stdio.h>

#include "rec-zonetocache.hh"
#include "recursor_cache.hh"

extern unique_ptr<MemRecursorCache> g_recCache;

BOOST_AUTO_TEST_SUITE(rec_zonetocache)

// A piece of the root zone
const std::string zone = ".			86400	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2021080900 1800 900 604800 86400\n"
                         ".			86400	IN	RRSIG	SOA 8 0 86400 20210822050000 20210809040000 26838 . IYvQp/mwMY9i8zGwc1azfS1lSHunX5SstuVXfZ5bNaZTp45SGLF7uzIAzX+/o1Dl5rKH27R8CE26dzTi5ds/OqsGrYXsTcdhwOQEmhYnfmKjGPFqfl0A6MLhHuyEkydPDdVxr5oMIEsIm0hMR1QDZS5gfpmcCfwTbkRGJP53yVnBAMHKhCK40k49YzN0PIycTBZgXu7dGWL2cfYlND1WLImcs1GPqu/8ND9tiLbhoDRw85kqLLR7IGPVb5xu/pNOfpX2nNkvBzC4M7bOaUAquxxetBSjMiPILSkC0XXsnQW7rsei7cmktt2CXU2IYqWkho8pe4A849TCzo1+Aheglw==\n"
                         ".			518400	IN	NS	a.root-servers.net.\n"
                         ".			518400	IN	NS	b.root-servers.net.\n"
                         ".			518400	IN	NS	c.root-servers.net.\n"
                         ".			518400	IN	NS	d.root-servers.net.\n"
                         ".			518400	IN	NS	e.root-servers.net.\n"
                         ".			518400	IN	NS	f.root-servers.net.\n"
                         ".			518400	IN	NS	g.root-servers.net.\n"
                         ".			518400	IN	NS	h.root-servers.net.\n"
                         ".			518400	IN	NS	i.root-servers.net.\n"
                         ".			518400	IN	NS	j.root-servers.net.\n"
                         ".			518400	IN	NS	k.root-servers.net.\n"
                         ".			518400	IN	NS	l.root-servers.net.\n"
                         ".			518400	IN	NS	m.root-servers.net.\n"
                         ".			518400	IN	RRSIG	NS 8 0 518400 20210822050000 20210809040000 26838 . rXMbGiqM2MOKVpykT064JBDF+4lrSisIWsL5Ro5pOnKJ4AELxsUSjFXRHtCpd6Ii3FUkdDUlhi4cGhWVK918sGadLKlVyks9IET1evutYk5u5w4EuUbaFelpLnGeT78QF6rbXRji3TDs3QeHQ8VqpHTnTiFSDVqIllTqF0DseiuIZ1IgT/Ho8PeX2oXAPEHfqcZbm3vmfZL8Ju+RyvbFpJ6f9AkuWMikIWjyz7xooNwJBjHtj3omIUo3BP+acbigSwmxwZaDgCbzyvtLxAU62WyNWeaOe6O5zwLR3fjhwCMBuVBm1qrA9Nmc9s5l/QzgIoI2SfE1/G7iwdwfXuU//g==\n"
                         ".			86400	IN	NSEC	aaa. NS SOA RRSIG NSEC DNSKEY\n"
                         ".			86400	IN	RRSIG	NSEC 8 0 86400 20210822050000 20210809040000 26838 . QQHXJDAkTPyrfP4MRSRsNz5AbVyYzPkyg3vCbUq9w144Bd0EjaXxGxd6zZ0dXVCKmf9UUpUvdbposIVqHeA3LLKmgRHXgkFMYxu2LbxoR+dnrcvNVBM/QFb+cHzQWLGl+D2is21UoUcfDKnPMNiWTxkUJNW4mTdVVIkck8FiBSwslrS4eD8irQJv9s6TbS9VYZQcI4UOqkd3XaFRox1UjzHkAVqN8Rv4O4IV0EW8yKGoMOJew/JBl8KCmWgqJDee1oMf6h2ZhBrwmF+uRiatl3wcfEGnquWKdq2ZSdzas6RbbO4T/oiJYoEL1TGmQ5hxzcbs+6AE+ixRk9m3+B7uuw==\n"
                         ".			172800	IN	DNSKEY	256 3 8 AwEAAbDEyqdwu2fqAwinPCFwALUCWfYYaLrNhnOrMxDorLBYMipEE1btlK1XnigTRMeb0YQ8/LCopb3CN73hYDhCHFsNk+GtukBB+gWLcg+2FZXbhLXIheQm8x2VfOHy2yYQG+18wjx3HY9Mj/ZEhXbZNrDMvpFKKVihWXa0/cHNg4ZcIHD9KkMlKzK+my1K/vz8fq5cFCFOu7wgM+kKbOikdcRBm7Uf/wRXZItFg2uhUijUb56gEN8uCUgmuEw6wQ5ZBuR7UT/FLyyAUeAH87oxF4im2DXK6J+JA7IAs2UHJ16uTqvdserUU8NIosislaXIZCvz+NTDb3SJcxs6bvCikeU=\n"
                         ".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=\n"
                         ".			172800	IN	RRSIG	DNSKEY 8 0 172800 20210821000000 20210731000000 20326 . MQCiL1+LRbTdEm3hyrUQOjMurN4QNmB7Up8ahSMS3vC+Waa7ywqKnClMNiZqPJKYuAn3wHZM0kj5pTF/wASaLJ9duxmcL6Wyi7mugRZE1Pv3RDvp6o4RbroZND9HVnImDxg/GmaJbRxtPuA/dGSp/Iq7AObJrtgNM81p19Z50Zn89POIr50/7SpuiRZ7xFYhfwIug9pgrHHdNQpQN7UVUJVXMDgtH/IT8ACgvGfoVLXCciPIpKJhwYZXq9nOGBgVxV7/h7aIGkrOryfm2ChvIei3MQANyjiq1QfckaXHpg+iHa4J6kduZoTR5Pe+E0VFpf8q63kYBaJTshOVVMm3TQ==\n"
                         "aaa.			172800	IN	NS	ns1.dns.nic.aaa.\n"
                         "aaa.			172800	IN	NS	ns2.dns.nic.aaa.\n"
                         "aaa.			172800	IN	NS	ns3.dns.nic.aaa.\n"
                         "aaa.			172800	IN	NS	ns4.dns.nic.aaa.\n"
                         "aaa.			172800	IN	NS	ns5.dns.nic.aaa.\n"
                         "aaa.			172800	IN	NS	ns6.dns.nic.aaa.\n"
                         "aaa.			86400	IN	DS	1657 8 1 0B0D56361CE62118537E07A680E9582F5F5FA129\n"
                         "aaa.			86400	IN	DS	1657 8 2 9D6BAE62219231C99FAA479716B6E4619330CE8206670AEA6C1673A055DC3AF2\n"
                         "aaa.			86400	IN	RRSIG	DS 8 1 86400 20210822050000 20210809040000 26838 . mZKBrX0gtfNXQ0VhUDcfmat7isb4YqGe110YF6VEdGcQZbcEjb+fsPBSriiHcBMcncOc57f+H0HDERe6Y0XlW8ZvLOPfH1AzOMHcc21Qgt0Zow4Dt06YAzX0ONw4FJUPyoHy2PPJhgldv6vywzHe9FzrAEoc/XB64tZjvNIp87HVP+YRhLi+3EFkWlnwhDJa/xvVGpPppyO+AX5Nh3VdWJ0awt72BwgZOyiqDgtfEjv3w1RGBa86I4hQ8QYR6PM9ghAPLhE/nMYnktzufTgnLpNhqhvWEvBDZlzXnRr51ZhRq2RZ/z6cdgnPITZM7aJCJfMZagRhLXujCWVrH9MFbw==\n"
                         "aaa.			86400	IN	NSEC	aarp. NS DS RRSIG NSEC\n"
                         "aaa.			86400	IN	RRSIG	NSEC 8 1 86400 20210822050000 20210809040000 26838 . iII7liwvc+VAAQRPVzeSl1kDRbYe3euoIyoVKdeHctNiXBef3TUkEQPytwkOSPmsrsIImQXiUo5RQWEjZdFCa4o1UJTeiDIrzYCu4sDdgtiSHkgsTdS6z9OmWCuyj1fLRaLBblRfZsGa+ObIU/IwhC+jm38SuCTPR3wwaizo934ck082zaUdmhioEXHq/wAum/Za9rNp8gJpL1GUib7U8BupwchWDcn6+VG5CnKN0N/R52K2PfEJ8JdXC8mM2Q0xJYN3aptPLqJzIqfstK874Hcsdw3Z5cG2LXTQZsnvqCg74tCwS6JgeYRPu/P7+yMoH349Ib/7WFGmM3iYW7M87w==\n"
                         "ns1.dns.nic.aaa.	172800	IN	A	156.154.144.2\n"
                         "ns1.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1071:0:0:0:0:2\n"
                         "ns2.dns.nic.aaa.	172800	IN	A	156.154.145.2\n"
                         "ns2.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1072:0:0:0:0:2\n"
                         "ns3.dns.nic.aaa.	172800	IN	A	156.154.159.2\n"
                         "ns3.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1073:0:0:0:0:2\n"
                         "ns4.dns.nic.aaa.	172800	IN	A	156.154.156.2\n"
                         "ns4.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1074:0:0:0:0:2\n"
                         "ns5.dns.nic.aaa.	172800	IN	A	156.154.157.2\n"
                         "ns5.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1075:0:0:0:0:2\n"
                         "ns6.dns.nic.aaa.	172800	IN	A	156.154.158.2\n"
                         "ns6.dns.nic.aaa.	172800	IN	AAAA	2610:a1:1076:0:0:0:0:2\n";

BOOST_AUTO_TEST_CASE(test_zonetocache)
{
  //g_slog = Logging::Logger::create(loggerBackend);

  char temp[] = "/tmp/ztcXXXXXXXXXX";
  int fd = mkstemp(temp);
  BOOST_REQUIRE(fd > 0);
  FILE* fp = fdopen(fd, "w");
  BOOST_REQUIRE(fp != nullptr);
  size_t written = fwrite(zone.data(), 1, zone.length(), fp);
  BOOST_REQUIRE(written == zone.length());
  BOOST_REQUIRE(fclose(fp) == 0);

  RecZoneToCache::Config config{".", "file", {temp}, ComboAddress(), TSIGTriplet()};
  config.d_refreshPeriod = 0;

  // Start with a new, empty cache
  g_recCache = std::make_unique<MemRecursorCache>();
  BOOST_CHECK_EQUAL(g_recCache->size(), 0U);
  RecZoneToCache::ZoneToCache(config, 0);
  unlink(temp);
  BOOST_CHECK_EQUAL(g_recCache->size(), 17U);

  std::vector<DNSRecord> retrieved;
  time_t now = time(nullptr);
  ComboAddress who;
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("."), QType::SOA, true, &retrieved, who), 0);
  // not auth
  BOOST_CHECK_LT(g_recCache->get(now, DNSName("aaa."), QType::NS, true, &retrieved, who), 0);
  // auth
  BOOST_CHECK_GT(g_recCache->get(now, DNSName("aaa."), QType::NS, false, &retrieved, who), 0);
}

BOOST_AUTO_TEST_SUITE_END()
