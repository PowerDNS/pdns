namespace pdns::rust::web::rec
{
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define WRAPPER(A) \
  void A(const Request& /* unused */, Response& /* unused */) {}

class Request;
class Response;

WRAPPER(apiDiscovery)
WRAPPER(apiDiscoveryV1)
WRAPPER(apiServer)
WRAPPER(apiServerCacheFlush)
WRAPPER(apiServerConfig)
WRAPPER(apiServerConfigAllowFromGET)
WRAPPER(apiServerConfigAllowFromPUT)
WRAPPER(apiServerConfigAllowNotifyFromGET)
WRAPPER(apiServerConfigAllowNotifyFromPUT)
WRAPPER(apiServerDetail)
WRAPPER(apiServerRPZStats)
WRAPPER(apiServerSearchData)
WRAPPER(apiServerStatistics)
WRAPPER(apiServerZoneDetailDELETE)
WRAPPER(apiServerZoneDetailGET)
WRAPPER(apiServerZoneDetailPUT)
WRAPPER(apiServerZonesGET)
WRAPPER(apiServerZonesPOST)
WRAPPER(jsonstat)
WRAPPER(prometheusMetrics)
WRAPPER(serveStuff)

#undef WRAPPER
}
