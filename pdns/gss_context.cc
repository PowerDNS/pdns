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

#include "gss_context.hh"
#include "logger.hh"

#ifndef ENABLE_GSS_TSIG

std::tuple<size_t, size_t, size_t> GssContext::getCounts() { return std::tuple<size_t, size_t, size_t>(0, 0, 0); }
bool GssContext::supported() { return false; }
GssContext::GssContext() :
  d_error(GSS_CONTEXT_UNSUPPORTED), d_type(GSS_CONTEXT_NONE) {}
GssContext::GssContext(const DNSName& /* label */) :
  d_error(GSS_CONTEXT_UNSUPPORTED), d_type(GSS_CONTEXT_NONE) {}
void GssContext::setLocalPrincipal(const std::string& /* name */) {}
bool GssContext::getLocalPrincipal(std::string& /* name */) { return false; }
void GssContext::setPeerPrincipal(const std::string& /* name */) {}
bool GssContext::getPeerPrincipal(std::string& /* name */) { return false; }
void GssContext::generateLabel(const std::string& /* suffix */) {}
void GssContext::setLabel(const DNSName& /* label */) {}
bool GssContext::init(const std::string& /* input */, std::string& /* output */) { return false; }
bool GssContext::accept(const std::string& /* input */, std::string& /* output */) { return false; }
bool GssContext::destroy() { return false; }
bool GssContext::expired() { return false; }
bool GssContext::valid() { return false; }
bool GssContext::sign(const std::string& /* input */, std::string& /* output */) { return false; }
bool GssContext::verify(const std::string& /* input */, const std::string& /* signature */) { return false; }
GssContextError GssContext::getError() { return GSS_CONTEXT_UNSUPPORTED; }

#else

#include <unordered_map>

#include "lock.hh"

#define TSIG_GSS_EXPIRE_INTERVAL 60

class GssCredential : boost::noncopyable
{
public:
  GssCredential(const std::string& name, const gss_cred_usage_t usage) :
    d_nameS(name), d_usage(usage)
  {
    gss_buffer_desc buffer;

    if (!name.empty()) {
      buffer.length = name.size();
      buffer.value = const_cast<void*>(static_cast<const void*>(name.c_str()));
      OM_uint32 min;
      auto maj = gss_import_name(&min, &buffer, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &d_name);
      if (maj != GSS_S_COMPLETE) {
        d_name = GSS_C_NO_NAME;
        d_valid = false;
        return;
      }
    }

    renew();
  };

  ~GssCredential()
  {
    OM_uint32 tmp_min __attribute__((unused));
    if (d_cred != GSS_C_NO_CREDENTIAL) {
      (void)gss_release_cred(&tmp_min, &d_cred);
    }
    if (d_name != GSS_C_NO_NAME) {
      (void)gss_release_name(&tmp_min, &d_name);
    }
  };

  bool expired() const
  {
    if (d_expires == -1) {
      return false;
    }
    return time(nullptr) > d_expires;
  }

  bool renew()
  {
    OM_uint32 time_rec, tmp_maj, tmp_min __attribute__((unused));
    tmp_maj = gss_acquire_cred(&tmp_min, d_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, d_usage, &d_cred, nullptr, &time_rec);

    if (tmp_maj != GSS_S_COMPLETE) {
      d_valid = false;
      (void)gss_release_name(&tmp_min, &d_name);
      d_name = GSS_C_NO_NAME;
      return false;
    }

    d_valid = true;

    // We do not want forever, but a good time
    if (time_rec == GSS_C_INDEFINITE) {
      time_rec = 24 * 60 * 60;
    }
    d_expires = time(nullptr) + time_rec;

    return true;
  }

  bool valid()
  {
    return d_valid && !expired();
  }

  std::string d_nameS;
  gss_cred_usage_t d_usage;
  gss_name_t d_name{GSS_C_NO_NAME};
  gss_cred_id_t d_cred{GSS_C_NO_CREDENTIAL};
  time_t d_expires{time(nullptr) + 60}; // partly initialized will be cleaned up
  bool d_valid{false};
}; // GssCredential

static LockGuarded<std::unordered_map<std::string, std::shared_ptr<GssCredential>>> s_gss_accept_creds;
static LockGuarded<std::unordered_map<std::string, std::shared_ptr<GssCredential>>> s_gss_init_creds;

class GssSecContext : boost::noncopyable
{
public:
  GssSecContext(std::shared_ptr<GssCredential> cred)
  {
    if (!cred->valid()) {
      throw PDNSException("Invalid credential " + cred->d_nameS);
    }
    d_cred = std::move(cred);
  }

  ~GssSecContext()
  {
    OM_uint32 tmp_maj __attribute__((unused)), tmp_min __attribute__((unused));
    if (d_ctx != GSS_C_NO_CONTEXT) {
      tmp_maj = gss_delete_sec_context(&tmp_min, &d_ctx, GSS_C_NO_BUFFER);
    }
    if (d_peer_name != GSS_C_NO_NAME) {
      tmp_maj = gss_release_name(&tmp_min, &(d_peer_name));
    }
  }

  std::shared_ptr<GssCredential> d_cred;
  GssContextType d_type{GSS_CONTEXT_NONE};
  gss_ctx_id_t d_ctx{GSS_C_NO_CONTEXT};
  gss_name_t d_peer_name{GSS_C_NO_NAME};
  time_t d_expires{time(nullptr) + 60}; // partly initialized will be cleaned up

  enum
  {
    GssStateInitial,
    GssStateNegotiate,
    GssStateComplete,
    GssStateError
  } d_state{GssStateInitial};
}; // GssSecContext

static LockGuarded<std::unordered_map<DNSName, std::shared_ptr<GssSecContext>>> s_gss_sec_context;

template <typename T>
static void doExpire(T& m, time_t now)
{
  auto lock = m.lock();
  for (auto i = lock->begin(); i != lock->end();) {
    if (now > i->second->d_expires) {
      i = lock->erase(i);
    }
    else {
      ++i;
    }
  }
}

static void expire()
{
  static time_t s_last_expired;
  time_t now = time(nullptr);
  if (now - s_last_expired < TSIG_GSS_EXPIRE_INTERVAL) {
    return;
  }
  s_last_expired = now;
  doExpire(s_gss_init_creds, now);
  doExpire(s_gss_accept_creds, now);
  doExpire(s_gss_sec_context, now);
}

bool GssContext::supported() { return true; }

void GssContext::initialize()
{
  d_peerPrincipal = "";
  d_localPrincipal = "";
  d_error = GSS_CONTEXT_NO_ERROR;
  d_type = GSS_CONTEXT_NONE;
}

GssContext::GssContext()
{
  initialize();
  generateLabel("pdns.tsig.");
}

GssContext::GssContext(const DNSName& label)
{
  initialize();
  setLabel(label);
}

void GssContext::generateLabel(const std::string& suffix)
{
  std::ostringstream oss;
  oss << std::hex << time(nullptr) << "." << suffix;
  setLabel(DNSName(oss.str()));
}

void GssContext::setLabel(const DNSName& label)
{
  d_label = label;
  auto lock = s_gss_sec_context.lock();
  auto it = lock->find(d_label);
  if (it != lock->end()) {
    d_secctx = it->second;
    d_type = d_secctx->d_type;
  }
}

bool GssContext::expired()
{
  return (!d_secctx || (d_secctx->d_expires > -1 && d_secctx->d_expires < time(nullptr)));
}

bool GssContext::valid()
{
  return (d_secctx && !expired() && d_secctx->d_state == GssSecContext::GssStateComplete);
}

bool GssContext::init(const std::string& input, std::string& output)
{
  expire();

  OM_uint32 tmp_maj __attribute__((unused)), tmp_min __attribute__((unused));
  OM_uint32 maj, min;
  gss_buffer_desc recv_tok, send_tok, buffer;
  OM_uint32 flags;
  OM_uint32 expires;

  if (d_label.empty()) {
    d_error = GSS_CONTEXT_INVALID;
    return false;
  }

  d_type = GSS_CONTEXT_INIT;
  std::shared_ptr<GssCredential> cred;
  {
    auto lock = s_gss_init_creds.lock();
    auto it = lock->find(d_localPrincipal);
    if (it == lock->end()) {
      it = lock->emplace(d_localPrincipal, std::make_shared<GssCredential>(d_localPrincipal, GSS_C_INITIATE)).first;
    }
    cred = it->second;
  }

  // see if we can find a context in non-completed state
  if (d_secctx) {
    if (d_secctx->d_state != GssSecContext::GssStateNegotiate) {
      d_error = GSS_CONTEXT_INVALID;
      return false;
    }
  }
  else {
    // make context
    auto lock = s_gss_sec_context.lock();
    d_secctx = std::make_shared<GssSecContext>(cred);
    d_secctx->d_state = GssSecContext::GssStateNegotiate;
    d_secctx->d_type = d_type;
    (*lock)[d_label] = d_secctx;
  }

  recv_tok.length = input.size();
  recv_tok.value = const_cast<void*>(static_cast<const void*>(input.c_str()));

  if (!d_peerPrincipal.empty()) {
    buffer.value = const_cast<void*>(static_cast<const void*>(d_peerPrincipal.c_str()));
    buffer.length = d_peerPrincipal.size();
    maj = gss_import_name(&min, &buffer, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &(d_secctx->d_peer_name));
    if (maj != GSS_S_COMPLETE) {
      processError("gss_import_name", maj, min);
      return false;
    }
  }

  maj = gss_init_sec_context(&min, cred->d_cred, &d_secctx->d_ctx, d_secctx->d_peer_name, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, &recv_tok, nullptr, &send_tok, &flags, &expires);

  if (send_tok.length > 0) {
    output.assign(static_cast<char*>(send_tok.value), send_tok.length);
    tmp_maj = gss_release_buffer(&tmp_min, &send_tok);
  }

  if (maj == GSS_S_COMPLETE) {
    // We do not want forever
    if (expires == GSS_C_INDEFINITE) {
      expires = 60;
    }
    d_secctx->d_expires = time(nullptr) + expires;
    d_secctx->d_state = GssSecContext::GssStateComplete;
    return true;
  }
  else if (maj != GSS_S_CONTINUE_NEEDED) {
    processError("gss_init_sec_context", maj, min);
  }

  return (maj == GSS_S_CONTINUE_NEEDED);
}

bool GssContext::accept(const std::string& input, std::string& output)
{
  expire();

  OM_uint32 tmp_maj __attribute__((unused)), tmp_min __attribute__((unused));
  OM_uint32 maj, min;
  gss_buffer_desc recv_tok, send_tok;
  OM_uint32 flags;
  OM_uint32 expires;

  if (d_label.empty()) {
    d_error = GSS_CONTEXT_INVALID;
    return false;
  }

  d_type = GSS_CONTEXT_ACCEPT;
  std::shared_ptr<GssCredential> cred;
  {
    auto lock = s_gss_accept_creds.lock();
    auto it = lock->find(d_localPrincipal);
    if (it == lock->end()) {
      it = lock->emplace(d_localPrincipal, std::make_shared<GssCredential>(d_localPrincipal, GSS_C_ACCEPT)).first;
    }
    cred = it->second;
  }

  // see if we can find a context in non-completed state
  if (d_secctx) {
    if (d_secctx->d_state != GssSecContext::GssStateNegotiate) {
      d_error = GSS_CONTEXT_INVALID;
      return false;
    }
  }
  else {
    // make context
    auto lock = s_gss_sec_context.lock();
    d_secctx = std::make_shared<GssSecContext>(cred);
    d_secctx->d_state = GssSecContext::GssStateNegotiate;
    d_secctx->d_type = d_type;
    (*lock)[d_label] = d_secctx;
  }

  recv_tok.length = input.size();
  recv_tok.value = const_cast<void*>(static_cast<const void*>(input.c_str()));

  maj = gss_accept_sec_context(&min, &d_secctx->d_ctx, cred->d_cred, &recv_tok, GSS_C_NO_CHANNEL_BINDINGS, &d_secctx->d_peer_name, nullptr, &send_tok, &flags, &expires, nullptr);

  if (send_tok.length > 0) {
    output.assign(static_cast<char*>(send_tok.value), send_tok.length);
    tmp_maj = gss_release_buffer(&tmp_min, &send_tok);
  }

  if (maj == GSS_S_COMPLETE) {
    // We do not want forever
    if (expires == GSS_C_INDEFINITE) {
      expires = 60;
    }
    d_secctx->d_expires = time(nullptr) + expires;
    d_secctx->d_state = GssSecContext::GssStateComplete;
    return true;
  }
  else if (maj != GSS_S_CONTINUE_NEEDED) {
    processError("gss_accept_sec_context", maj, min);
  }
  return (maj == GSS_S_CONTINUE_NEEDED);
};

bool GssContext::sign(const std::string& input, std::string& output)
{
  OM_uint32 tmp_maj __attribute__((unused)), tmp_min __attribute__((unused));
  OM_uint32 maj, min;

  gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;

  recv_tok.length = input.size();
  recv_tok.value = const_cast<void*>(static_cast<const void*>(input.c_str()));

  maj = gss_get_mic(&min, d_secctx->d_ctx, GSS_C_QOP_DEFAULT, &recv_tok, &send_tok);

  if (send_tok.length > 0) {
    output.assign(static_cast<char*>(send_tok.value), send_tok.length);
    tmp_maj = gss_release_buffer(&tmp_min, &send_tok);
  }

  if (maj != GSS_S_COMPLETE) {
    processError("gss_get_mic", maj, min);
  }

  return (maj == GSS_S_COMPLETE);
}

bool GssContext::verify(const std::string& input, const std::string& signature)
{
  OM_uint32 maj, min;

  gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc sign_tok = GSS_C_EMPTY_BUFFER;

  recv_tok.length = input.size();
  recv_tok.value = const_cast<void*>(static_cast<const void*>(input.c_str()));
  sign_tok.length = signature.size();
  sign_tok.value = const_cast<void*>(static_cast<const void*>(signature.c_str()));

  maj = gss_verify_mic(&min, d_secctx->d_ctx, &recv_tok, &sign_tok, nullptr);

  if (maj != GSS_S_COMPLETE) {
    processError("gss_get_mic", maj, min);
  }

  return (maj == GSS_S_COMPLETE);
}

bool GssContext::destroy()
{
  if (d_label.empty()) {
    return false;
  }
  auto lock = s_gss_sec_context.lock();
  return lock->erase(d_label) == 1;
}

void GssContext::setLocalPrincipal(const std::string& name)
{
  d_localPrincipal = name;
}

bool GssContext::getLocalPrincipal(std::string& name)
{
  name = d_localPrincipal;
  return name.size() > 0;
}

void GssContext::setPeerPrincipal(const std::string& name)
{
  d_peerPrincipal = name;
}

bool GssContext::getPeerPrincipal(std::string& name)
{
  gss_buffer_desc value;
  OM_uint32 maj, min;

  if (d_secctx->d_peer_name != GSS_C_NO_NAME) {
    maj = gss_display_name(&min, d_secctx->d_peer_name, &value, nullptr);
    if (maj == GSS_S_COMPLETE && value.length > 0) {
      name.assign(static_cast<char*>(value.value), value.length);
      maj = gss_release_buffer(&min, &value);
      return true;
    }
    else {
      return false;
    }
  }
  else {
    return false;
  }
}

std::tuple<size_t, size_t, size_t> GssContext::getCounts()
{
  return {s_gss_init_creds.lock()->size(), s_gss_accept_creds.lock()->size(), s_gss_sec_context.lock()->size()};
}

void GssContext::processError(const std::string& method, OM_uint32 maj, OM_uint32 min)
{
  OM_uint32 tmp_min;
  gss_buffer_desc msg;
  OM_uint32 msg_ctx;

  msg_ctx = 0;
  while (1) {
    ostringstream oss;
    if (gss_display_status(&tmp_min, maj, GSS_C_GSS_CODE, GSS_C_NULL_OID, &msg_ctx, &msg) == GSS_S_COMPLETE) {
      oss << method << ": " << msg.value;
    }
    else {
      oss << method << ": ?";
    }
    if (msg.length != 0) {
      gss_release_buffer(&tmp_min, &msg);
    }
    d_gss_errors.push_back(oss.str());
    if (!msg_ctx)
      break;
  }
  msg_ctx = 0;
  while (1) {
    ostringstream oss;
    if (gss_display_status(&tmp_min, min, GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &msg) == GSS_S_COMPLETE) {
      oss << method << ": " << msg.value;
    }
    else {
      oss << method << ": ?";
    }
    if (msg.length != 0) {
      gss_release_buffer(&tmp_min, &msg);
    }
    d_gss_errors.push_back(oss.str());
    if (!msg_ctx)
      break;
  }
}

#endif

bool gss_add_signature(const DNSName& context, const std::string& message, std::string& mac)
{
  string tmp_mac;
  GssContext gssctx(context);
  if (!gssctx.valid()) {
    g_log << Logger::Error << "GSS context '" << context << "' is not valid" << endl;
    for (const string& error : gssctx.getErrorStrings()) {
      g_log << Logger::Error << "GSS error: " << error << endl;
      ;
    }
    return false;
  }

  if (!gssctx.sign(message, tmp_mac)) {
    g_log << Logger::Error << "Could not sign message using GSS context '" << context << "'" << endl;
    for (const string& error : gssctx.getErrorStrings()) {
      g_log << Logger::Error << "GSS error: " << error << endl;
      ;
    }
    return false;
  }
  mac = std::move(tmp_mac);
  return true;
}

bool gss_verify_signature(const DNSName& context, const std::string& message, const std::string& mac)
{
  GssContext gssctx(context);
  if (!gssctx.valid()) {
    g_log << Logger::Error << "GSS context '" << context << "' is not valid" << endl;
    for (const string& error : gssctx.getErrorStrings()) {
      g_log << Logger::Error << "GSS error: " << error << endl;
      ;
    }
    return false;
  }

  if (!gssctx.verify(message, mac)) {
    g_log << Logger::Error << "Could not verify message using GSS context '" << context << "'" << endl;
    for (const string& error : gssctx.getErrorStrings()) {
      g_log << Logger::Error << "GSS error: " << error << endl;
      ;
    }
    return false;
  }
  return true;
}
