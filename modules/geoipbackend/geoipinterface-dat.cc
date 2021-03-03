/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "geoipbackend.hh"
#include "geoipinterface.hh"
#ifdef HAVE_GEOIP
#include "GeoIPCity.h"
#include "GeoIP.h"

struct geoip_deleter
{
  void operator()(GeoIP* ptr)
  {
    if (ptr) {
      GeoIP_delete(ptr);
    }
  };
};

struct geoiprecord_deleter
{
  void operator()(GeoIPRecord* ptr)
  {
    if (ptr) {
      GeoIPRecord_delete(ptr);
    }
  }
};

struct geoipregion_deleter
{
  void operator()(GeoIPRegion* ptr)
  {
    if (ptr) {
      GeoIPRegion_delete(ptr);
    }
  }
};

class GeoIPInterfaceDAT : public GeoIPInterface
{
public:
  GeoIPInterfaceDAT(const string& fname, const string& modeStr)
  {
    int flags;
    if (modeStr == "standard")
      flags = GEOIP_STANDARD;
    else if (modeStr == "memory")
      flags = GEOIP_MEMORY_CACHE;
    else if (modeStr == "index")
      flags = GEOIP_INDEX_CACHE;
#ifdef HAVE_MMAP
    else if (modeStr == "mmap")
      flags = GEOIP_MMAP_CACHE;
#endif
    else
      throw PDNSException("Invalid cache mode " + modeStr + " for GeoIP backend");

    d_gi = std::unique_ptr<GeoIP, geoip_deleter>(GeoIP_open(fname.c_str(), flags));
    if (d_gi.get() == nullptr)
      throw PDNSException("Cannot open GeoIP database " + fname);
    d_db_type = GeoIP_database_edition(d_gi.get());
  }

  bool queryCountry(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_COUNTRY_EDITION || d_db_type == GEOIP_LARGE_COUNTRY_EDITION) {
      int id;
      if ((id = GeoIP_id_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl)) > 0) {
        ret = GeoIP_code3_by_id(id);
        gl.netmask = tmp_gl.netmask;
        return true;
      }
    }
    else if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1) {
      std::unique_ptr<GeoIPRegion, geoipregion_deleter> gir(GeoIP_region_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl));
      if (gir) {
        gl.netmask = tmp_gl.netmask;
        ret = GeoIP_code3_by_id(GeoIP_id_by_code(gir->country_code));
        return true;
      }
    }
    else if (d_db_type == GEOIP_CITY_EDITION_REV0 || d_db_type == GEOIP_CITY_EDITION_REV1) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = gir->country_code3;
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryCountryV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_COUNTRY_EDITION_V6 || d_db_type == GEOIP_LARGE_COUNTRY_EDITION_V6) {
      int id;
      if ((id = GeoIP_id_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl)) > 0) {
        ret = GeoIP_code3_by_id(id);
        gl.netmask = tmp_gl.netmask;
        return true;
      }
    }
    else if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1) {
      std::unique_ptr<GeoIPRegion, geoipregion_deleter> gir(GeoIP_region_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl));
      if (gir) {
        gl.netmask = tmp_gl.netmask;
        ret = GeoIP_code3_by_id(GeoIP_id_by_code(gir->country_code));
        return true;
      }
    }
    else if (d_db_type == GEOIP_CITY_EDITION_REV0_V6 || d_db_type == GEOIP_CITY_EDITION_REV1_V6) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr_v6(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = gir->country_code3;
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryCountry2(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_COUNTRY_EDITION || d_db_type == GEOIP_LARGE_COUNTRY_EDITION) {
      int id;
      if ((id = GeoIP_id_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl)) > 0) {
        ret = GeoIP_code_by_id(id);
        gl.netmask = tmp_gl.netmask;
        return true;
      }
    }
    else if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1) {
      std::unique_ptr<GeoIPRegion, geoipregion_deleter> gir(GeoIP_region_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl));
      if (gir) {
        gl.netmask = tmp_gl.netmask;
        ret = GeoIP_code_by_id(GeoIP_id_by_code(gir->country_code));
        return true;
      }
    }
    else if (d_db_type == GEOIP_CITY_EDITION_REV0 || d_db_type == GEOIP_CITY_EDITION_REV1) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = gir->country_code;
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryCountry2V6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_COUNTRY_EDITION_V6 || d_db_type == GEOIP_LARGE_COUNTRY_EDITION_V6) {
      int id;
      if ((id = GeoIP_id_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl)) > 0) {
        ret = GeoIP_code_by_id(id);
        gl.netmask = tmp_gl.netmask;
        return true;
      }
    }
    else if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1) {
      std::unique_ptr<GeoIPRegion, geoipregion_deleter> gir(GeoIP_region_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl));
      if (gir) {
        gl.netmask = tmp_gl.netmask;
        ret = GeoIP_code_by_id(GeoIP_id_by_code(gir->country_code));
        return true;
      }
    }
    else if (d_db_type == GEOIP_CITY_EDITION_REV0_V6 || d_db_type == GEOIP_CITY_EDITION_REV1_V6) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr_v6(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = gir->country_code;
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryContinent(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_COUNTRY_EDITION || d_db_type == GEOIP_LARGE_COUNTRY_EDITION) {
      int id;
      if ((id = GeoIP_id_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl)) > 0) {
        ret = GeoIP_continent_by_id(id);
        gl.netmask = tmp_gl.netmask;
        return true;
      }
    }
    else if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1) {
      std::unique_ptr<GeoIPRegion, geoipregion_deleter> gir(GeoIP_region_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl));
      if (gir) {
        gl.netmask = tmp_gl.netmask;
        ret = GeoIP_continent_by_id(GeoIP_id_by_code(gir->country_code));
        return true;
      }
    }
    else if (d_db_type == GEOIP_CITY_EDITION_REV0 || d_db_type == GEOIP_CITY_EDITION_REV1) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = ret = GeoIP_continent_by_id(GeoIP_id_by_code(gir->country_code));
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryContinentV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_COUNTRY_EDITION_V6 || d_db_type == GEOIP_LARGE_COUNTRY_EDITION_V6) {
      int id;
      if ((id = GeoIP_id_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl)) > 0) {
        ret = GeoIP_continent_by_id(id);
        gl.netmask = tmp_gl.netmask;
        return true;
      }
    }
    else if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1) {
      std::unique_ptr<GeoIPRegion, geoipregion_deleter> gir(GeoIP_region_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl));
      if (gir) {
        gl.netmask = tmp_gl.netmask;
        ret = GeoIP_continent_by_id(GeoIP_id_by_code(gir->country_code));
        return true;
      }
    }
    else if (d_db_type == GEOIP_CITY_EDITION_REV0_V6 || d_db_type == GEOIP_CITY_EDITION_REV1_V6) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr_v6(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = GeoIP_continent_by_id(GeoIP_id_by_code(gir->country_code));
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryName(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_ISP_EDITION || d_db_type == GEOIP_ORG_EDITION) {
      char* result = GeoIP_name_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl);
      if (result != nullptr) {
        ret = result;
        free(result);
        gl.netmask = tmp_gl.netmask;
        // reduce space to dash
        ret = boost::replace_all_copy(ret, " ", "-");
        return true;
      }
    }
    return false;
  }

  bool queryNameV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_ISP_EDITION_V6 || d_db_type == GEOIP_ORG_EDITION_V6) {
      char* result = GeoIP_name_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl);
      if (result != nullptr) {
        ret = result;
        free(result);
        gl.netmask = tmp_gl.netmask;
        // reduce space to dash
        ret = boost::replace_all_copy(ret, " ", "-");
        return true;
      }
    }
    return false;
  }

  bool queryASnum(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_ASNUM_EDITION) {
      char* result = GeoIP_name_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl);
      if (result != nullptr) {
        std::string val(result);
        vector<string> asnr;
        free(result);
        stringtok(asnr, val);
        if (asnr.size() > 0) {
          gl.netmask = tmp_gl.netmask;
          ret = asnr[0];
          return true;
        }
      }
    }
    return false;
  }

  bool queryASnumV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_ASNUM_EDITION_V6) {
      char* result = GeoIP_name_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl);
      if (result != nullptr) {
        std::string val(result);
        vector<string> asnr;
        free(result);
        stringtok(asnr, val);
        if (asnr.size() > 0) {
          gl.netmask = tmp_gl.netmask;
          ret = asnr[0];
          return true;
        }
      }
    }
    return false;
  }

  bool queryRegion(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1) {
      std::unique_ptr<GeoIPRegion, geoipregion_deleter> gir(GeoIP_region_by_addr_gl(d_gi.get(), ip.c_str(), &tmp_gl));
      if (gir) {
        gl.netmask = tmp_gl.netmask;
        ret = valueOrEmpty<char*, string>(gir->region);
        return true;
      }
    }
    else if (d_db_type == GEOIP_CITY_EDITION_REV0 || d_db_type == GEOIP_CITY_EDITION_REV1) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = valueOrEmpty<char*, string>(gir->region);
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryRegionV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    GeoIPLookup tmp_gl = {
      .netmask = gl.netmask,
    };
    if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1) {
      std::unique_ptr<GeoIPRegion, geoipregion_deleter> gir(GeoIP_region_by_addr_v6_gl(d_gi.get(), ip.c_str(), &tmp_gl));
      if (gir) {
        gl.netmask = tmp_gl.netmask;
        ret = valueOrEmpty<char*, string>(gir->region);
        return true;
      }
    }
    else if (d_db_type == GEOIP_CITY_EDITION_REV0_V6 || d_db_type == GEOIP_CITY_EDITION_REV1_V6) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr_v6(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = valueOrEmpty<char*, string>(gir->region);
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryCity(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    if (d_db_type == GEOIP_CITY_EDITION_REV0 || d_db_type == GEOIP_CITY_EDITION_REV1) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = valueOrEmpty<char*, string>(gir->city);
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryCityV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    if (d_db_type == GEOIP_CITY_EDITION_REV0_V6 || d_db_type == GEOIP_CITY_EDITION_REV1_V6) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr_v6(d_gi.get(), ip.c_str()));
      if (gir) {
        ret = valueOrEmpty<char*, string>(gir->city);
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryLocationV6(GeoIPNetmask& gl, const string& ip,
    double& latitude, double& longitude,
    boost::optional<int>& alt, boost::optional<int>& prec) override
  {
    if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1 || d_db_type == GEOIP_CITY_EDITION_REV0_V6 || d_db_type == GEOIP_CITY_EDITION_REV1_V6) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr_v6(d_gi.get(), ip.c_str()));
      if (gir) {
        latitude = gir->latitude;
        longitude = gir->longitude;
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  bool queryLocation(GeoIPNetmask& gl, const string& ip,
    double& latitude, double& longitude,
    boost::optional<int>& alt, boost::optional<int>& prec) override
  {
    if (d_db_type == GEOIP_REGION_EDITION_REV0 || d_db_type == GEOIP_REGION_EDITION_REV1 || d_db_type == GEOIP_CITY_EDITION_REV0 || d_db_type == GEOIP_CITY_EDITION_REV1) {
      std::unique_ptr<GeoIPRecord, geoiprecord_deleter> gir(GeoIP_record_by_addr(d_gi.get(), ip.c_str()));
      if (gir) {
        latitude = gir->latitude;
        longitude = gir->longitude;
        gl.netmask = gir->netmask;
        return true;
      }
    }
    return false;
  }

  ~GeoIPInterfaceDAT() {}

private:
  unsigned int d_db_type;
  unique_ptr<GeoIP, geoip_deleter> d_gi;
};

unique_ptr<GeoIPInterface> GeoIPInterface::makeDATInterface(const string& fname, const map<string, string>& opts)
{
  string mode = "standard";
  const auto& opt = opts.find("mode");
  if (opt != opts.end())
    mode = opt->second;
  return unique_ptr<GeoIPInterface>(new GeoIPInterfaceDAT(fname, mode));
}

#else

unique_ptr<GeoIPInterface> GeoIPInterface::makeDATInterface(const string& fname, const map<string, string>& opts)
{
  throw PDNSException("libGeoIP support not compiled in");
}

#endif
