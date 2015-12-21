
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnscrypt.hh"

#ifdef HAVE_DNSCRYPT
int handleDnsCryptQuery(DnsCryptContext* ctx, char* packet, uint16_t len, std::shared_ptr<DnsCryptQuery>& query, uint16_t* decryptedQueryLen, bool tcp, std::vector<uint8_t>& response)
{
  query->ctx = ctx;

  ctx->parsePacket(packet, len, query, tcp, decryptedQueryLen);

  if (query->valid == false) {
    vinfolog("Dropping DnsCrypt invalid query");
    return false;
  }

  if (query->encrypted == false) {
    ctx->getCertificateResponse(query, response);

    return false;
  }

  if(*decryptedQueryLen < (int)sizeof(struct dnsheader)) {
    g_stats.nonCompliantQueries++;
    return false;
  }

  return true;
}
#endif
