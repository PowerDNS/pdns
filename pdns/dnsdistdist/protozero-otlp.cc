#include "protozero-otlp.hh"
#include "protozero-trace.hh"
#include <vector>

namespace pdns::trace
{

void ExportTraceServiceRequest::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, resource_spans);
}

ExportTraceServiceRequest ExportTraceServiceRequest::decode(protozero::pbf_reader& reader)
{
  ExportTraceServiceRequest ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      protozero::pbf_reader sub = reader.get_message();
      ret.resource_spans.emplace_back(ResourceSpans::decode(sub));
      break;
    }
  }
  return ret;
}

bool ExportTraceServiceRequest::operator==(const ExportTraceServiceRequest& rhs) const
{
  return resource_spans == rhs.resource_spans;
}

void ExportTracePartialSuccess::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, rejected_spans);
  pdns::trace::encode(writer, 2, error_message);
}

ExportTracePartialSuccess ExportTracePartialSuccess::decode(protozero::pbf_reader& reader)
{
  ExportTracePartialSuccess ret{
    .rejected_spans = 0,
    .error_message = "",
  };

  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      ret.rejected_spans = reader.get_int64();
      break;
    case 2:
      ret.error_message = reader.get_string();
      break;
    }
  }
  return ret;
}

bool ExportTracePartialSuccess::operator==(const ExportTracePartialSuccess& rhs) const
{
  return (rejected_spans == rhs.rejected_spans && error_message == rhs.error_message);
}

void ExportTraceServiceResponse::encode(protozero::pbf_writer& writer) const
{
  protozero::pbf_writer sub{writer, 1};
  partial_success.encode(sub);
}

ExportTraceServiceResponse ExportTraceServiceResponse::decode(protozero::pbf_reader& reader)
{
  ExportTraceServiceResponse ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      auto sub = reader.get_message();
      ret.partial_success = ExportTracePartialSuccess::decode(sub);
      break;
    }
  }
  return ret;
}

bool ExportTraceServiceResponse::operator==(const ExportTraceServiceResponse& rhs) const
{
  return partial_success == rhs.partial_success;
}
}
