namespace pdns::rust::web::rec {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define WRAPPER(A) void A(const Request& /* unused */ , Response& /* unused */) { }

WRAPPER(jsonstat)
WRAPPER(apiServerCacheFlush)
WRAPPER(apiServerDetail)
WRAPPER(apiServerZonesGET)
WRAPPER(apiServerZonesPOST)
WRAPPER(prometheusMetrics)
WRAPPER(serveStuff)
WRAPPER(apiServerStatistics)

#undef WRAPPER
}
