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
#include "pdns/logging.hh"

class GeoIPInterfaceMMDB : public GeoIPInterface
{
public:
  struct GeoIPMMDBQueries
  {
    std::vector<std::string> asname;
    std::vector<std::string> asnum;
    std::vector<std::string> city;
    std::vector<std::string> city_alt;
    std::vector<std::string> continent;
    std::vector<std::string> country;
    std::vector<std::string> latitude;
    std::vector<std::string> longitude;
    std::vector<std::string> precision;
    std::vector<std::string> region;
  };

  GeoIPInterfaceMMDB(Logr::log_t slog, const string& fname, const string& modeStr, GeoIPMMDBQueries& queries) :
    d_slog(slog), d_queries(std::move(queries))
  {
    int ec;
    int flags = 0;
    if (modeStr == "") {
      /* for the benefit of ifdef */
      ;
    }
#ifdef HAVE_MMAP
    else if (modeStr == "mmap") {
      flags |= MMDB_MODE_MMAP;
    }
#endif
    else {
      throw PDNSException(string("Unsupported mode ") + modeStr + ("for geoipbackend-mmdb"));
    }
    memset(&d_s, 0, sizeof(d_s));
    if ((ec = MMDB_open(fname.c_str(), flags, &d_s)) != MMDB_SUCCESS) {
      throw PDNSException(string("Cannot open ") + fname + string(": ") + string(MMDB_strerror(ec)));
    }
    SLOG(g_log << Logger::Debug << "Opened MMDB database " << fname << "(type: " << d_s.metadata.database_type << " version: " << d_s.metadata.binary_format_major_version << "." << d_s.metadata.binary_format_minor_version << ")" << endl,
         d_slog->info(Logr::Debug, "Opened MMDB database", "file", Logging::Loggable(fname), "type", Logging::Loggable(d_s.metadata.database_type), "major_version", Logging::Loggable(d_s.metadata.binary_format_major_version), "minor_version", Logging::Loggable(d_s.metadata.binary_format_minor_version)));
  }

  bool queryCountry(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.country)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  };

  bool queryCountryV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.country)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  };

  bool queryCountry2(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    return queryCountry(ret, gl, ip);
  }

  bool queryCountry2V6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    return queryCountryV6(ret, gl, ip);
  }

  bool queryContinent(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.continent)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryContinentV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.continent)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryName(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.asname)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryNameV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.asname)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryASnum(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.asnum)) {
      return false;
    }
    ret = std::to_string(data.uint32);
    return true;
  }

  bool queryASnumV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.asnum)) {
      return false;
    }
    ret = std::to_string(data.uint32);
    return true;
  }

  bool queryRegion(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.region)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryRegionV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.region)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryCity(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.city) && !mmdbGetValue(res, data, d_queries.city_alt)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryCityV6(string& ret, GeoIPNetmask& gl, const string& ip) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.city) && !mmdbGetValue(res, data, d_queries.city_alt)) {
      return false;
    }
    ret = string(data.utf8_string, data.data_size);
    return true;
  }

  bool queryLocation(GeoIPNetmask& gl, const string& ip,
                     double& latitude, double& longitude,
                     std::optional<int>& /* alt */, std::optional<int>& prec) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, false, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.latitude)) {
      return false;
    }
    latitude = data.double_value;
    if (!mmdbGetValue(res, data, d_queries.longitude)) {
      return false;
    }
    longitude = data.double_value;
    if (!mmdbGetValue(res, data, d_queries.precision)) {
      return false;
    }
    prec = data.uint16;
    return true;
  }

  bool queryLocationV6(GeoIPNetmask& gl, const string& ip,
                       double& latitude, double& longitude,
                       std::optional<int>& /* alt */, std::optional<int>& prec) override
  {
    MMDB_entry_data_s data;
    MMDB_lookup_result_s res;
    if (!mmdbLookup(ip, true, gl, res)) {
      return false;
    }
    if (!mmdbGetValue(res, data, d_queries.latitude)) {
      return false;
    }
    latitude = data.double_value;
    if (!mmdbGetValue(res, data, d_queries.longitude)) {
      return false;
    }
    longitude = data.double_value;
    if (!mmdbGetValue(res, data, d_queries.precision)) {
      return false;
    }
    prec = data.uint16;
    return true;
  }

  ~GeoIPInterfaceMMDB() override { MMDB_close(&d_s); };

private:
  MMDB_s d_s;
  Logr::log_t d_slog;
  GeoIPMMDBQueries d_queries;

  // This is a wrapper around MMDB_aget_value.
  bool mmdbGetValue(MMDB_lookup_result_s& res, MMDB_entry_data_s& data, const std::vector<std::string>& path)
  {
    // We unfortunately can not instantiate std::array with a non-compile-time
    // known size (here path.size() + 1), so pick some constant which ought
    // to be large enough for our use cases.
    std::array<const char*, 8 + 1> arr{};
    if (path.size() + 1 > arr.size()) {
      throw PDNSException("MMDB path contains too many components");
    }
    for (size_t itemno = 0; itemno < path.size(); ++itemno) {
      arr.at(itemno) = path.at(itemno).c_str();
    }
    arr.at(path.size()) = nullptr;
    return MMDB_aget_value(&res.entry, &data, arr.data()) == MMDB_SUCCESS && data.has_data;
  }

  bool mmdbLookup(const string& ip, bool v6, GeoIPNetmask& gl, MMDB_lookup_result_s& res)
  {
    int gai_ec = 0, mmdb_ec = 0;
    res = MMDB_lookup_string(&d_s, ip.c_str(), &gai_ec, &mmdb_ec);

    if (gai_ec != 0) {
      SLOG(g_log << Logger::Warning << "MMDB_lookup_string(" << ip << ") failed: " << gai_strerror(gai_ec) << endl,
           d_slog->error(Logr::Warning, gai_strerror(gai_ec), "MMDB lookup failed", "ip", Logging::Loggable(ip)));
    }
    else if (mmdb_ec != MMDB_SUCCESS) {
      SLOG(g_log << Logger::Warning << "MMDB_lookup_string(" << ip << ") failed: " << MMDB_strerror(mmdb_ec) << endl,
           d_slog->error(Logr::Warning, MMDB_strerror(mmdb_ec), "MMDB lookup failed", "ip", Logging::Loggable(ip)));
    }
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

static void parsePath(std::vector<std::string>& path, const std::map<std::string, std::string>& opts, const std::string& name, const std::string& deflt)
{
  const auto& opt = opts.find(name);
  if (opt == opts.end()) {
    stringtok(path, deflt, "/");
  }
  else {
    stringtok(path, opt->second, "/");
  }
}

unique_ptr<GeoIPInterface> GeoIPInterface::makeMMDBInterface(Logr::log_t slog, const string& fname, const map<string, string>& opts)
{
  string mode = "";
  string language = "en";
  const auto& opt_mode = opts.find("mode");
  if (opt_mode != opts.end())
    mode = opt_mode->second;

  // MMDB "queries", as database paths
  GeoIPInterfaceMMDB::GeoIPMMDBQueries queries;
  parsePath(queries.asname, opts, "query-asname", "autonomous_system_organization");
  parsePath(queries.asnum, opts, "query-asnum", "autonomous_system_number");
  parsePath(queries.city, opts, "query-city", "cities/0");
  // If there is no specified alternate query for city names, make sure the
  // default value uses the configured language parameter, if any, for backwards
  // compatibility.
  std::string city_alt_default = "city/names/";
  if (opts.find("query-city_alt") == opts.end()) {
    const auto& opt_language = opts.find("language");
    if (opt_language != opts.end()) {
      city_alt_default.append(opt_language->second);
    }
    else {
      city_alt_default.append("en");
    }
  }
  parsePath(queries.city_alt, opts, "query-city-alt", city_alt_default);
  parsePath(queries.continent, opts, "query-continent", "continent/code");
  parsePath(queries.country, opts, "query-country", "country/iso_code");
  parsePath(queries.latitude, opts, "query-latitude", "location/latitude");
  parsePath(queries.longitude, opts, "query-longitude", "location/longitude");
  parsePath(queries.precision, opts, "query-precision", "location/accuracy_radius");
  parsePath(queries.region, opts, "query-region", "subdivisions/0/iso_code");

  return std::make_unique<GeoIPInterfaceMMDB>(slog, fname, mode, queries);
}

#else

unique_ptr<GeoIPInterface> GeoIPInterface::makeMMDBInterface([[maybe_unused]] Logr::log_t slog, [[maybe_unused]] const string& fname, [[maybe_unused]] const map<string, string>& opts)
{
  throw PDNSException("libmaxminddb support not compiled in");
}

#endif
