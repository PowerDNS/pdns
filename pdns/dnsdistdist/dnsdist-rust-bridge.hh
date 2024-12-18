#pragma once

#include <memory>
#include <string>

class DNSAction;
class DNSResponseAction;
class DNSRule;

#include "rust/cxx.h"

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

struct ProtobufLoggersConfiguration;
struct DnstapLoggersConfiguration;
struct KeyValueStoresConfiguration;

void registerProtobufLogger(const ProtobufLoggersConfiguration& config);
void registerDnstapLogger(const DnstapLoggersConfiguration& config);
void registerKVSObjects(const KeyValueStoresConfiguration& config);

#include "dnsdist-rust-bridge-actions-generated.hh"
#include "dnsdist-rust-bridge-selectors-generated.hh"
}
