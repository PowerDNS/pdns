#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include <cstdio>
#include <math.h>
#include <cstdlib>
#include <sys/types.h>
#include <string>
#include <errno.h>
#include "dnsrecords.hh"

static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
  1000000, 10000000, 100000000, 1000000000};

/* converts ascii size/precision X * 10**Y(cm) to 0xXY. moves pointer.*/
static uint8_t precsize_aton(const char** strptr)
{
  unsigned int mval = 0, cmval = 0;
  uint8_t retval = 0;
  const char* cp;
  int exponent;
  int mantissa;

  cp = *strptr;

  while (isdigit(*cp))
    mval = mval * 10 + (*cp++ - '0');

  if (*cp == '.') { /* centimeters */
    cp++;
    if (isdigit(*cp)) {
      cmval = (*cp++ - '0') * 10;
      if (isdigit(*cp)) {
        cmval += (*cp++ - '0');
      }
    }
  }
  cmval = (mval * 100) + cmval;

  for (exponent = 0; exponent < 9; exponent++)
    if (cmval < poweroften[exponent + 1])
      break;

  mantissa = cmval / poweroften[exponent];
  if (mantissa > 9)
    mantissa = 9;

  retval = (mantissa << 4) | exponent;

  *strptr = cp;

  return (retval);
}

/* converts ascii lat/lon to unsigned encoded 32-bit number.
 *  moves pointer. */
static uint32_t
latlon2ul(const char** latlonstrptr, int* which)
{
  const char* cp;
  uint32_t retval;
  int deg = 0, min = 0, secs = 0, secsfrac = 0;

  cp = *latlonstrptr;

  while (isdigit(*cp))
    deg = deg * 10 + (*cp++ - '0');

  while (isspace(*cp))
    cp++;

  if (!(isdigit(*cp)))
    goto fndhemi;

  while (isdigit(*cp))
    min = min * 10 + (*cp++ - '0');

  while (isspace(*cp))
    cp++;

  if (*cp && !(isdigit(*cp)))
    goto fndhemi;

  while (isdigit(*cp))
    secs = secs * 10 + (*cp++ - '0');

  if (*cp == '.') { /* decimal seconds */
    cp++;
    if (isdigit(*cp)) {
      secsfrac = (*cp++ - '0') * 100;
      if (isdigit(*cp)) {
        secsfrac += (*cp++ - '0') * 10;
        if (isdigit(*cp)) {
          secsfrac += (*cp++ - '0');
        }
      }
    }
  }

  while (*cp && !isspace(*cp)) /* if any trailing garbage */
    cp++;

  while (isspace(*cp))
    cp++;

fndhemi:
  switch (*cp) {
  case 'N':
  case 'n':
  case 'E':
  case 'e':
    retval = ((unsigned)1 << 31)
      + (((((deg * 60) + min) * 60) + secs) * 1000)
      + secsfrac;
    break;
  case 'S':
  case 's':
  case 'W':
  case 'w':
    retval = ((unsigned)1 << 31)
      - (((((deg * 60) + min) * 60) + secs) * 1000)
      - secsfrac;
    break;
  default:
    retval = 0; /* invalid value -- indicates error */
    break;
  }

  switch (*cp) {
  case 'N':
  case 'n':
  case 'S':
  case 's':
    *which = 1; /* latitude */
    break;
  case 'E':
  case 'e':
  case 'W':
  case 'w':
    *which = 2; /* longitude */
    break;
  default:
    *which = 0; /* error */
    break;
  }

  if (!*cp)
    return 0;

  cp++; /* skip the hemisphere */

  while (*cp && !isspace(*cp)) /* if any trailing garbage */
    cp++;

  while (isspace(*cp)) /* move to next field */
    cp++;

  *latlonstrptr = cp;

  return (retval);
}

void LOCRecordContent::report(void)
{
  regist(1, QType::LOC, &make, &make, "LOC");
  regist(254, QType::LOC, &make, &make, "LOC");
}

std::shared_ptr<DNSRecordContent> LOCRecordContent::make(const string& content)
{
  return std::make_shared<LOCRecordContent>(content);
}

void LOCRecordContent::toPacket(DNSPacketWriter& pw)
{
  pw.xfr8BitInt(d_version);
  pw.xfr8BitInt(d_size);
  pw.xfr8BitInt(d_horizpre);
  pw.xfr8BitInt(d_vertpre);

  pw.xfr32BitInt(d_latitude);
  pw.xfr32BitInt(d_longitude);
  pw.xfr32BitInt(d_altitude);
}

std::shared_ptr<LOCRecordContent::DNSRecordContent> LOCRecordContent::make(const DNSRecord& dr, PacketReader& pr)
{
  auto ret = std::make_shared<LOCRecordContent>();
  pr.xfr8BitInt(ret->d_version);
  pr.xfr8BitInt(ret->d_size);
  pr.xfr8BitInt(ret->d_horizpre);
  pr.xfr8BitInt(ret->d_vertpre);

  pr.xfr32BitInt(ret->d_latitude);
  pr.xfr32BitInt(ret->d_longitude);
  pr.xfr32BitInt(ret->d_altitude);

  return ret;
}

LOCRecordContent::LOCRecordContent(const string& content, const string& zone)
{
  // 51 59 00.000 N 5 55 00.000 E 4.00m 1.00m 10000.00m 10.00m
  // convert this to d_version, d_size, d_horiz/vertpre, d_latitude, d_longitude, d_altitude
  d_version = 0;

  const char *cp, *maxcp;

  uint32_t lltemp1 = 0, lltemp2 = 0;
  int altmeters = 0, altfrac = 0, altsign = 1;
  d_horizpre = 0x16; /* default = 1e6 cm = 10000.00m = 10km */
  d_vertpre = 0x13; /* default = 1e3 cm = 10.00m */
  d_size = 0x12; /* default = 1e2 cm = 1.00m */
  int which1 = 0, which2 = 0;

  cp = content.c_str();
  maxcp = cp + strlen(content.c_str());

  lltemp1 = latlon2ul(&cp, &which1);
  lltemp2 = latlon2ul(&cp, &which2);

  switch (which1 + which2) {
  case 3: /* 1 + 2, the only valid combination */
    if ((which1 == 1) && (which2 == 2)) { /* normal case */
      d_latitude = lltemp1;
      d_longitude = lltemp2;
    }
    else if ((which1 == 2) && (which2 == 1)) { /*reversed*/
      d_latitude = lltemp1;
      d_longitude = lltemp2;
    }
    else { /* some kind of brokenness */
      return;
    }
    break;
  default: /* we didn't get one of each */
    throw MOADNSException("Error decoding LOC content");
  }

  /* altitude */
  if (*cp == '-') {
    altsign = -1;
    cp++;
  }

  if (*cp == '+')
    cp++;

  while (isdigit(*cp))
    altmeters = altmeters * 10 + (*cp++ - '0');

  if (*cp == '.') { /* decimal meters */
    cp++;
    if (isdigit(*cp)) {
      altfrac = (*cp++ - '0') * 10;
      if (isdigit(*cp)) {
        altfrac += (*cp++ - '0');
      }
    }
  }

  d_altitude = (10000000 + (altsign * (altmeters * 100 + altfrac)));

  while (!isspace(*cp) && (cp < maxcp))
    /* if trailing garbage or m */
    cp++;

  while (isspace(*cp) && (cp < maxcp))
    cp++;

  if (cp >= maxcp)
    goto defaults;

  d_size = precsize_aton(&cp);

  while (!isspace(*cp) && (cp < maxcp)) /*if trailing garbage or m*/
    cp++;

  while (isspace(*cp) && (cp < maxcp))
    cp++;

  if (cp >= maxcp)
    goto defaults;

  d_horizpre = precsize_aton(&cp);

  while (!isspace(*cp) && (cp < maxcp)) /*if trailing garbage or m*/
    cp++;

  while (isspace(*cp) && (cp < maxcp))
    cp++;

  if (cp >= maxcp)
    goto defaults;

  d_vertpre = precsize_aton(&cp);

defaults:;
}

string LOCRecordContent::getZoneRepresentation(bool noDot) const
{
  // convert d_version, d_size, d_horiz/vertpre, d_latitude, d_longitude, d_altitude to:
  // 51 59 00.000 N 5 55 00.000 E 4.00m 1.00m 10000.00m 10.00m

  double latitude = ((int32_t)d_latitude - (1 << 31)) / 3600000.0;
  double longitude = ((int32_t)d_longitude - (1 << 31)) / 3600000.0;
  double altitude = ((int32_t)d_altitude) / 100.0 - 100000;

  double size = 0.01 * ((d_size >> 4) & 0xf);
  int count = d_size & 0xf;
  while (count--)
    size *= 10;

  double horizpre = 0.01 * ((d_horizpre >> 4) & 0xf);
  count = d_horizpre & 0xf;
  while (count--)
    horizpre *= 10;

  double vertpre = 0.01 * ((d_vertpre >> 4) & 0xf);
  count = d_vertpre & 0xf;
  while (count--)
    vertpre *= 10;

  double remlat = 60.0 * (latitude - (int)latitude);
  double remlong = 60.0 * (longitude - (int)longitude);
  static const boost::format fmt("%d %d %2.03f %c %d %d %2.03f %c %.2fm %.2fm %.2fm %.2fm");
  std::string ret = boost::str(
    boost::format(fmt)
    % abs((int)latitude) % abs((int)((latitude - (int)latitude) * 60))
    % fabs((double)((remlat - (int)remlat) * 60.0)) % (latitude > 0 ? 'N' : 'S')
    % abs((int)longitude) % abs((int)((longitude - (int)longitude) * 60))
    % fabs((double)((remlong - (int)remlong) * 60.0)) % (longitude > 0 ? 'E' : 'W')
    % altitude % size
    % horizpre % vertpre);

  return ret;
}
