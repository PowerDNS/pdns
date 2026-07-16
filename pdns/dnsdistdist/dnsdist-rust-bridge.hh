#pragma once

#include <memory>
#include <string>

class DNSAction;
class DNSResponseAction;
class DNSRule;

#include "rust/cxx.h"

/* the following replaces the default handling of exceptions
   thrown from C++ code called from Rust. It is necessary because
   some of our legacy code uses the special PDNSException that does
   not inherit from std::exception
*/
#include "pdnsexception.hh"

namespace rust::behavior
{

template <typename Try, typename Fail>
static void trycatch(Try&& func, Fail&& fail) noexcept
{
  try {
    func();
  }
  catch (const std::exception& exp) {
    fail(exp.what());
  }
  catch (const PDNSException& exp) {
    fail(exp.reason);
  }
}

}

namespace dnsdist::rust::settings
{

struct DNSSelector
{
  std::shared_ptr<DNSRule> d_rule;
  std::string d_name;
};

struct DNSActionWrapper
{
  std::shared_ptr<DNSAction> d_action;
  std::string d_name;
};

struct DNSResponseActionWrapper
{
  std::shared_ptr<DNSResponseAction> d_action;
  std::string d_name;
};

struct ProtobufLoggerConfiguration;
struct DnstapLoggerConfiguration;
struct OtlpLoggerConfiguration;
struct KeyValueStoresConfiguration;
struct MmdbConfiguration;
struct NetmaskGroupConfiguration;
struct TimedIpSetConfiguration;

void registerProtobufLogger(const ProtobufLoggerConfiguration& config);
void registerDnstapLogger(const DnstapLoggerConfiguration& config);
void registerOtlpLogger(const OtlpLoggerConfiguration& config);
void registerKVSObjects(const KeyValueStoresConfiguration& config);
void registerMMDBObjects(const ::rust::Vec<MmdbConfiguration>& config);
void registerNMGObjects(const ::rust::Vec<NetmaskGroupConfiguration>& nmgs);
void registerTimedIPSetObjects(const ::rust::Vec<TimedIpSetConfiguration>& sets);

#include "dnsdist-rust-bridge-actions-generated.hh"
#include "dnsdist-rust-bridge-selectors-generated.hh"
}
