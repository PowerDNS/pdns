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

#ifdef HAVE_MMDB

#include "maxminddb.h"

class GeoIPInterfaceMMDB : public GeoIPInterface {
public:
  GeoIPInterfaceMMDB(const string &fname, const string &modeStr, const string& language) {
    int ec;
    int flags = 0;
    if (modeStr == "")
      /* for the benefit of ifdef */
      ;
#ifdef HAVE_MMAP
    else if (modeStr == "mmap")
      flags |= MMDB_MODE_MMAP;
#endif
    else
      throw PDNSException(string("Unsupported mode ") + modeStr + ("for geoipbackend-mmdb"));
    memset(&d_s, 0, sizeof(d_s));
    if ((ec = MMDB_open(fname.c_str(), flags, &d_s)) < 0)
      throw PDNSException(string("Cannot open ") + fname + string(": ") + string(MMDB_strerror(ec)));
    d_lang = language;
    g_log<<Logger::Debug<<"Opened MMDB database "<<fname<<"(type: "<<d_s.metadata.database_type<<
                      " version: "<<d_s.metadata.binary_format_major_version << "." <<
                      d_s.metadata.binary_format_minor_version << ")" << endl;
  }

  bool queryCountry(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "country", "iso_code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  };

  bool queryCountryV6(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "country", "iso_code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  };

  bool queryCountry2(string &ret, GeoIPNetmask& gl, const string &ip) override {
    return queryCountry(ret, gl, ip);
  }

  bool queryCountry2V6(string &ret, GeoIPNetmask& gl, const string &ip) override {
    return queryCountryV6(ret, gl, ip);
  }

  bool queryContinent(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "continent", "code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true; 
  }

  bool queryContinentV6(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "continent", "code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryName(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "autonomous_system_organization", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryNameV6(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "autonomous_system_organization", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryASnum(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "autonomous_system_number", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = std::to_string(data.uint32);
    return true;
  }

  bool queryASnumV6(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "autonomous_system_number", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = std::to_string(data.uint32);
    return true;
  }

  bool queryRegion(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "subdivisions", "0", "iso_code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryRegionV6(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "subdivisions", "0", "iso_code", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryCity(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res))
      return false;
    if ((MMDB_get_value(&res.entry, &data, "cities", "0", NULL) != MMDB_SUCCESS || !data.has_data) &&
        (MMDB_get_value(&res.entry, &data, "city", "names", d_lang.c_str(), NULL) != MMDB_SUCCESS || !data.has_data))
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryCityV6(string &ret, GeoIPNetmask& gl, const string &ip) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res))
      return false;
    if ((MMDB_get_value(&res.entry, &data, "cities", "0", NULL) != MMDB_SUCCESS || !data.has_data) &&
        (MMDB_get_value(&res.entry, &data, "city", "names", d_lang.c_str(), NULL) != MMDB_SUCCESS || !data.has_data))
      return false;
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryLocation(GeoIPNetmask& gl, const string &ip,
                     double& latitude, double& longitude,
                     boost::optional<int>& alt, boost::optional<int>& prec) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "location", "latitude", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    latitude = data.double_value;
     if (MMDB_get_value(&res.entry, &data, "location", "longitude", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    longitude = data.double_value;
    if (MMDB_get_value(&res.entry, &data, "location", "accuracy_radius", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    prec = data.uint16;
    return true;
  }

  bool queryLocationV6(GeoIPNetmask& gl, const string &ip,
                       double& latitude, double& longitude,
                       boost::optional<int>& alt, boost::optional<int>& prec) override {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res))
      return false;
    if (MMDB_get_value(&res.entry, &data, "location", "latitude", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    latitude = data.double_value;
     if (MMDB_get_value(&res.entry, &data, "location", "longitude", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    longitude = data.double_value;
    if (MMDB_get_value(&res.entry, &data, "location", "accuracy_radius", NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
    prec = data.uint16;
    return true;
  }

  ~GeoIPInterfaceMMDB() { MMDB_close(&d_s); };
private:
  MMDB_s d_s;
  string d_lang;

  bool mmdbLookup(const string &ip, bool v6, GeoIPNetmask& gl, MMDB_lookup_result_s& res) {
    int gai_ec = 0, mmdb_ec = 0;
    res = MMDB_lookup_string(&d_s, ip.c_str(), &gai_ec, &mmdb_ec);
 
    if (gai_ec != 0)
      g_log<<Logger::Warning<<"MMDB_lookup_string("<<ip<<") failed: "<<gai_strerror(gai_ec)<<endl;
    else if (mmdb_ec != MMDB_SUCCESS)
      g_log<<Logger::Warning<<"MMDB_lookup_string("<<ip<<") failed: "<<MMDB_strerror(mmdb_ec)<<endl;
    else if (res.found_entry) {
      gl.netmask = res.netmask;
      /* If it's a IPv6 database, IPv4 netmasks are reduced from 128, so we need to deduct
         96 to get from [96,128] => [0,32] range */
      if (!v6 && gl.netmask > 32)
        gl.netmask -= 96;
      return true;
    }
    return false;
  }
};

unique_ptr<GeoIPInterface> GeoIPInterface::makeMMDBInterface(const string &fname, const map<string, string>& opts) {
  string mode = "";
  string language = "en";
  const auto &opt_mode = opts.find("mode");
  if (opt_mode != opts.end())
    mode = opt_mode->second;
  const auto &opt_lang = opts.find("language");
  if (opt_lang != opts.end())
    language = opt_lang->second;
  return unique_ptr<GeoIPInterface>(new GeoIPInterfaceMMDB(fname, mode, language));
}

#else

unique_ptr<GeoIPInterface> GeoIPInterface::makeMMDBInterface(const string &fname, const map<string, string>& opts) {
  throw PDNSException("libmaxminddb support not compiled in");
}

#endif
