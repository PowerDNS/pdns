#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <algorithm>
#include <boost/format.hpp>

#include "utility.hh"
#include <cstdio>
#include <cmath>
#include <cstdlib>
#include <sys/types.h>
#include <string>
#include <cerrno>
#include "dnsrecords.hh"

const static std::array<unsigned int,10> poweroften = {
  1, 10, 100, 1000, 10000, 100000,
  1000000,10000000,100000000,1000000000
};

enum coordtype { LATITUDE, LONGITUDE };

// Skip whitespace.
static void
skipspace(const std::string& content, std::string::size_type& pos)
{
  while (pos < content.length() && std::isspace(content.at(pos)) != 0) {
    ++pos;
  }
}

// Skip 'm' and following whitespace if present.
static void
skipm(const std::string& content, std::string::size_type& pos)
{
  if (pos < content.length()) {
    switch (content.at(pos)) {
    case 'M': case 'm':
      ++pos;
      skipspace(content, pos);
      break;
    default:
      break;
    }
  }
}


// Parse an unsigned integer, and skip following whitespace if present.
static bool
parsenum(const std::string& content, std::string::size_type& pos, unsigned int& number)
{
  bool parsed{false};

  number = 0;
  while (pos < content.length() && std::isdigit(content.at(pos)) != 0) {
    parsed = true;
    number = number * 10 + (content.at(pos) - '0');
    ++pos;
  }
  skipspace(content, pos);
  return parsed;
}

// Parse the fractional part of an integer up to the given number of digits,
// and skip following whitespace if present.
static bool
parsefrac(const std::string& content, std::string::size_type& pos, unsigned int digits, unsigned int& number)
{
  bool parsed{false};

  number = 0;
  if (pos < content.length() && content.at(pos) == '.') {
    ++pos;
    while (digits-- != 0) {
      number *= 10;
      if (pos < content.length() && std::isdigit(content.at(pos)) != 0) {
        parsed = true; // intentionally rejects '.' alone
        number += (content.at(pos) - '0');
        ++pos;
      }
    }
    // skip any further digits
    while (pos < content.length() && std::isdigit(content.at(pos)) != 0) {
      ++pos;
    }
  }
  skipspace(content, pos);
  return parsed;
}

// Parse an integer with up to two fractional digits, convert it to
// X * 10**Y, cap X and Y at 9, and return 0xXY.
static uint8_t precsize_aton(const std::string& content, std::string::size_type& pos)
{
  unsigned int mval = 0;
  unsigned int cmval = 0;
  unsigned int exponent{};
  unsigned int mantissa{};

  if (!parsenum(content, pos, mval)) {
    throw MOADNSException("Expecting a size or precision in LOC contents");
  }
  parsefrac(content, pos, 2, cmval);
  skipm(content, pos);

  cmval = (mval * 100) + cmval;
  // We could compute exponent and mantissa by repeatedly dividing by 10,
  // this array search comes from RFC1876.
  for (exponent = 0; exponent < 9; exponent++) {
    if (cmval < poweroften.at(exponent+1)) {
      break;
    }
  }
  mantissa = cmval / poweroften.at(exponent);
  mantissa = std::min(mantissa, 9U);

  return (mantissa << 4) | exponent;
}

// Converts text representation of latitude or longitude into an unsigned
// encoded 32-bit number. Returns the type and updates the position within
// the string.
// Expected format: DEG [MIN [SEC[.FRAC]]] (N|S|E|W)
static uint32_t
latlon2ul(const std::string& content, std::string::size_type& pos, coordtype& type)
{
  unsigned int deg = 0;
  unsigned int min = 0;
  unsigned int secs = 0;
  unsigned int secsfrac = 0;

  if (!parsenum(content, pos, deg)) {
    throw MOADNSException("Expecting a latitude or longitude in LOC contents");
  }

  if (parsenum(content, pos, min)) {
    if (min >= 60) {
      throw MOADNSException("Invalid latitude or longitude minutes in LOC contents");
    }
    if (parsenum(content, pos, secs)) {
      parsefrac(content, pos, 3, secsfrac);
      // According to RFC1876, we should reject 60.000, but records with such
      // values appear in the unit tests, and there is probably a reason behind
      // that, so allow this value for now. FIXME?
      if (secs > 60 || (secs == 60 && secsfrac > 0)) {
std::cerr << content << std::endl;
        throw MOADNSException("Invalid latitude or longitude seconds in LOC contents");
      }
    }
  }

  if (pos >= content.length()) {
    throw MOADNSException("Expecting hemisphere in LOC contents");
  }

  uint32_t retval = (((((deg * 60) + min) * 60) + secs) * 1000) + secsfrac;

  switch (content.at(pos)) {
  case 'N': case 'n':
    type = LATITUDE;
    retval = (1U<<31) + retval;
    break;
  case 'E': case 'e':
    type = LONGITUDE;
    retval = (1U<<31) + retval;
    break;
  case 'S': case 's':
    type = LATITUDE;
    retval = (1U<<31) - retval;
    break;
  case 'W': case 'w':
    type = LONGITUDE;
    retval = (1U<<31) - retval;
    break;
  default:
    throw MOADNSException("Invalid hemisphere specification in LOC contents");
  }

  if (type == LATITUDE && deg > 90) {
    throw MOADNSException("Invalid latitude degrees in LOC contents");
  }
  if (type == LONGITUDE && deg > 180) {
    throw MOADNSException("Invalid longitude degrees in LOC contents");
  }

  ++pos;
  skipspace(content, pos);

  return retval;
}

void LOCRecordContent::report(const ReportIsOnlyCallableByReportAllTypes& /* unused */)
{
  regist(1, QType::LOC, &make, &make, "LOC");
  regist(254, QType::LOC, &make, &make, "LOC");
}

std::shared_ptr<DNSRecordContent> LOCRecordContent::make(const string& content)
{
  return std::make_shared<LOCRecordContent>(content);
}


void LOCRecordContent::toPacket(DNSPacketWriter& pw) const
{
  pw.xfr8BitInt(d_version);
  pw.xfr8BitInt(d_size);
  pw.xfr8BitInt(d_horizpre);
  pw.xfr8BitInt(d_vertpre);

  pw.xfr32BitInt(d_latitude);
  pw.xfr32BitInt(d_longitude);
  pw.xfr32BitInt(d_altitude);
}

std::shared_ptr<LOCRecordContent::DNSRecordContent> LOCRecordContent::make(const DNSRecord& /* dr */, PacketReader& pr)
{
  auto ret=std::make_shared<LOCRecordContent>();
  pr.xfr8BitInt(ret->d_version);
  pr.xfr8BitInt(ret->d_size);
  pr.xfr8BitInt(ret->d_horizpre);
  pr.xfr8BitInt(ret->d_vertpre);

  pr.xfr32BitInt(ret->d_latitude);
  pr.xfr32BitInt(ret->d_longitude);
  pr.xfr32BitInt(ret->d_altitude);

  return ret;
}

// 51 59 00.000 N 5 55 00.000 E 4.00m 1.00m 10000.00m 10.00m
// convert this to d_version, d_size, d_horiz/vertpre, d_latitude, d_longitude, d_altitude
LOCRecordContent::LOCRecordContent(const string& content, const string& /* zone */)
{
  std::string::size_type pos{0};

  // Parse latitude and longitude, in any order
  coordtype type1{};
  auto lltemp1 = latlon2ul(content, pos, type1);
  coordtype type2{};
  auto lltemp2 = latlon2ul(content, pos, type2);
  if (type1 == type2) {
    throw MOADNSException("Expecting latitude and longitude in LOC contents");
  }
  if (type1 == LATITUDE) {
    d_latitude = lltemp1;
    d_longitude = lltemp2;
  }
  else {
    d_longitude = lltemp1;
    d_latitude = lltemp2;
  }

  // Parse optional altitude
  if (pos < content.length()) {
    unsigned int altmeters = 0;
    unsigned int altfrac = 0;
    int altsign = 1;
    if (content.at(pos) == '-') {
      altsign = -1;
      ++pos;
    }
    else if (content.at(pos) == '+') {
      ++pos;
    }
    if (!parsenum(content, pos, altmeters)) {
      throw MOADNSException("Expecting altitude in LOC contents");
    }
    parsefrac(content, pos, 2, altfrac);
    skipm(content, pos);
    d_altitude += altsign * (altmeters * 100 + altfrac);
  }

  // Parse optional size and precision
  if (pos < content.length()) {
    d_size = precsize_aton(content, pos);
  }
  if (pos < content.length()) {
    d_horizpre = precsize_aton(content, pos);
  }
  if (pos < content.length()) {
    d_vertpre = precsize_aton(content, pos);
  }
}


string LOCRecordContent::getZoneRepresentation(bool /* noDot */) const
{
  // convert d_version, d_size, d_horiz/vertpre, d_latitude, d_longitude, d_altitude to:
  // 51 59 00.000 N 5 55 00.000 E 4.00m 1.00m 10000.00m 10.00m

  double altitude= static_cast<int32_t>(d_altitude) / 100.0 - 100000;

  double size=0.01*((d_size>>4)&0xf);
  unsigned int count = d_size & 0xf;
  while (count-- != 0) {
    size*=10;
  }

  double horizpre=0.01*((d_horizpre>>4) & 0xf);
  count = d_horizpre & 0xf;
  while (count-- != 0) {
    horizpre*=10;
  }

  double vertpre=0.01*((d_vertpre>>4)&0xf);
  count = d_vertpre & 0xf;
  while (count-- != 0) {
    vertpre*=10;
  }

  char hemLat = 'N';
  uint32_t lat = d_latitude;
  if (lat >= 1U << 31) {
    lat -= 1U << 31;
  }
  else {
    hemLat = 'S';
    lat = (1U << 31) - lat;
  }
  auto fracLat = lat % 1000;
  lat /= 1000;
  auto secLat = lat % 60;
  lat /= 60;
  auto minutesLat = lat % 60;
  auto degreesLat = lat / 60;

  char hemLon= 'E';
  uint32_t lon = d_longitude;
  if (lon >= 1U << 31) {
    lon -= 1U << 31;
  }
  else {
    hemLon = 'W';
    lon = (1U << 31) - lon;
  }
  auto fracLon = lon % 1000;
  lon /= 1000;
  auto secLon = lon % 60;
  lon /= 60;
  auto minutesLon = lon % 60;
  auto degreesLon = lon / 60;

  static const boost::format fmt("%d %d %d.%03d %c %d %d %d.%03d %c %.2fm %.2fm %.2fm %.2fm");
  std::string ret = boost::str(
    boost::format(fmt)
    % degreesLat % minutesLat % secLat % fracLat % hemLat
    % degreesLon % minutesLon % secLon % fracLon % hemLon
    % altitude % size
    % horizpre % vertpre
    );

  return ret;
}
