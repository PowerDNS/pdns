
#include "dns.hh"
#include "ednsoptions.hh"
#include "iputils.hh"

/* extract a specific EDNS0 option from a pointer on the beginning rdLen of the OPT RR */
int getEDNSOption(char* optRR, const size_t len, uint16_t wantedOption, char ** optionValue, size_t * optionValueSize)
{
  assert(optRR != NULL);
  assert(optionValue != NULL);
  assert(optionValueSize != NULL);
  size_t pos = 0;
  if (len < DNS_RDLENGTH_SIZE)
    return EINVAL;

  const uint16_t rdLen = (((unsigned char) optRR[pos]) * 256) + ((unsigned char) optRR[pos+1]);
  size_t rdPos = 0;
  pos += DNS_RDLENGTH_SIZE;
  if ((pos + rdLen) > len) {
    return EINVAL;
  }

  while(len >= (pos + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE) &&
        rdLen >= (rdPos + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) {
    const uint16_t optionCode = (((unsigned char) optRR[pos]) * 256) + ((unsigned char) optRR[pos+1]);
    pos += EDNS_OPTION_CODE_SIZE;
    rdPos += EDNS_OPTION_CODE_SIZE;
    const uint16_t optionLen = (((unsigned char) optRR[pos]) * 256) + ((unsigned char) optRR[pos+1]);
    pos += EDNS_OPTION_LENGTH_SIZE;
    rdPos += EDNS_OPTION_LENGTH_SIZE;
    if (optionLen > (rdLen - rdPos) || optionLen > (len - pos))
      return EINVAL;

    if (optionCode == wantedOption) {
      *optionValue = optRR + pos - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE);
      *optionValueSize = optionLen + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE;
      return 0;
    }
    else {
      /* skip this option */
      pos += optionLen;
      rdPos += optionLen;
    }
  }

  return ENOENT;
}

void generateEDNSOption(uint16_t optionCode, const std::string& payload, std::string& res)
{
  const uint16_t ednsOptionCode = htons(optionCode);
  const uint16_t payloadLen = htons(payload.length());
  res.append((const char *) &ednsOptionCode, sizeof ednsOptionCode);
  res.append((const char *) &payloadLen, sizeof payloadLen);
  res.append(payload);
}
