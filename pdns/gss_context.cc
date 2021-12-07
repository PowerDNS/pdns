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

#include "lock.hh"
#include "logger.hh"

#ifndef ENABLE_GSS_TSIG

bool GssContext::supported() { return false; }
GssContext::GssContext() :
  d_error(GSS_CONTEXT_UNSUPPORTED), d_type(GSS_CONTEXT_NONE) {}
GssContext::GssContext(const DNSName& label) :
  d_error(GSS_CONTEXT_UNSUPPORTED), d_type(GSS_CONTEXT_NONE) {}
void GssContext::setLocalPrincipal(const std::string& name) {}
bool GssContext::getLocalPrincipal(std::string& name) { return false; }
void GssContext::setPeerPrincipal(const std::string& name) {}
bool GssContext::getPeerPrincipal(std::string& name) { return false; }
void GssContext::generateLabel(const std::string& suffix) {}
void GssContext::setLabel(const DNSName& label) {}
bool GssContext::init(const std::string& input, std::string& output) { return false; }
bool GssContext::accept(const std::string& input, std::string& output) { return false; }
bool GssContext::destroy() { return false; }
bool GssContext::expired() { return false; }
bool GssContext::valid() { return false; }
bool GssContext::sign(const std::string& input, std::string& output) { return false; }
bool GssContext::verify(const std::string& input, const std::string& signature) { return false; }
GssContextError GssContext::getError() { return GSS_CONTEXT_UNSUPPORTED; }

#else

static string gsserror(OM_uint32 status_code)
{
  OM_uint32 maj_status;
  OM_uint32 min_status;
  OM_uint32 message_context = 0;
  gss_buffer_desc status_string;
  std::basic_ostringstream<char> ret;
  bool first = true;
  do {
    if (!first) {
      ret << '/';
    } else {
      first = false;
    }
    maj_status = gss_display_status(&min_status,
                                    status_code,
                                    GSS_C_GSS_CODE,
                                    GSS_C_NO_OID,
                                    &message_context,
                                    &status_string);
    if (maj_status == GSS_S_COMPLETE) {
      ret << string(static_cast<char*>(status_string.value), status_string.length);
      gss_release_buffer(&min_status, &status_string);
    } else {
      // XXX to release or not to release?
      ret << std::to_string(status_code);
    }
  } while (message_context != 0);
  return ret.str();
}

class GssCredential : boost::noncopyable
{
public:
  GssCredential(const std::string& name, const gss_cred_usage_t usage) :
    d_valid(false), d_nameS(name), d_name(GSS_C_NO_NAME), d_cred(GSS_C_NO_CREDENTIAL), d_usage(usage)
  {
    gss_buffer_desc buffer;

    if (!name.empty()) {
      buffer.length = name.size();
      buffer.value = const_cast<void*>(static_cast<const void*>(name.c_str()));
      d_maj = gss_import_name(&d_min, &buffer, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &d_name);
      if (d_maj != GSS_S_COMPLETE) {
        d_name = GSS_C_NO_NAME;
        d_valid = false;
        return;
      }
    }

    renew();
  };

  ~GssCredential()
  {
    OM_uint32 tmp_maj __attribute__((unused)), tmp_min __attribute__((unused));
    if (d_cred != GSS_C_NO_CREDENTIAL)
      tmp_maj = gss_release_cred(&tmp_min, &d_cred);
    if (d_name != GSS_C_NO_NAME)
      tmp_maj = gss_release_name(&tmp_min, &d_name);
  };

  bool expired() const
  {
    if (d_expires == -1)
      return false;
    return time(nullptr) > d_expires;
  }

  bool renew()
  {
    OM_uint32 time_rec, tmp_maj __attribute__((unused)), tmp_min __attribute__((unused));
    d_maj = gss_acquire_cred(&d_min, d_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, d_usage, &d_cred, nullptr, &time_rec);

    if (d_maj != GSS_S_COMPLETE) {
      d_valid = false;
      tmp_maj = gss_release_name(&tmp_min, &d_name);
      d_name = GSS_C_NO_NAME;
      return false;
    }

    d_valid = true;

    if (time_rec > GSS_C_INDEFINITE) {
      d_expires = time(nullptr) + time_rec;
    }
    else {
      d_expires = -1;
    }

    return true;
  }

  bool valid()
  {
    return d_valid && !expired();
  }

  OM_uint32 d_maj, d_min;

  bool d_valid;
  int64_t d_expires;
  std::string d_nameS;
  gss_name_t d_name;
  gss_cred_id_t d_cred;
  gss_cred_usage_t d_usage;
};

LockGuarded<std::map<std::string, std::shared_ptr<GssCredential>>> s_gss_accept_creds;
LockGuarded<std::map<std::string, std::shared_ptr<GssCredential>>> s_gss_init_creds;

class GssSecContext : boost::noncopyable
{
public:
  GssSecContext(std::shared_ptr<GssCredential> cred)
  {
    if (!cred->valid()) {
      throw PDNSException("Invalid credential " + cred->d_nameS + ": " + gsserror(cred->d_maj));
    }
    d_cred = cred;
    d_state = GssStateInitial;
    d_ctx = GSS_C_NO_CONTEXT;
    d_expires = 0;
    d_maj = d_min = 0;
    d_peer_name = GSS_C_NO_NAME;
    d_type = GSS_CONTEXT_NONE;
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

  GssContextType d_type;
  gss_ctx_id_t d_ctx;
  gss_name_t d_peer_name;
  int64_t d_expires;
  std::shared_ptr<GssCredential> d_cred;
  OM_uint32 d_maj, d_min;

  enum
  {
    GssStateInitial,
    GssStateNegotiate,
    GssStateComplete,
    GssStateError
  } d_state;
};

LockGuarded<std::map<DNSName, std::shared_ptr<GssSecContext>>> s_gss_sec_context;

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
  if (lock->find(d_label) != lock->end()) {
    d_ctx = (*lock)[d_label];
    d_type = d_ctx->d_type;
  }
}

bool GssContext::expired()
{
  return (!d_ctx || (d_ctx->d_expires > -1 && d_ctx->d_expires < time(nullptr)));
}

bool GssContext::valid()
{
  return (d_ctx && !expired() && d_ctx->d_state == GssSecContext::GssStateComplete);
}

bool GssContext::init(const std::string& input, std::string& output)
{
  OM_uint32 tmp_maj __attribute__((unused)), tmp_min __attribute__((unused));
  OM_uint32 maj, min;
  gss_buffer_desc recv_tok, send_tok, buffer;
  OM_uint32 flags;
  OM_uint32 expires;

  std::shared_ptr<GssCredential> cred;
  if (d_label.empty()) {
    d_error = GSS_CONTEXT_INVALID;
    return false;
  }

  d_type = GSS_CONTEXT_INIT;

  {
    auto lock = s_gss_init_creds.lock();
    if (lock->find(d_localPrincipal) != lock->end()) {
      cred = (*lock)[d_localPrincipal];
    }
    else {
      (*lock)[d_localPrincipal] = std::make_shared<GssCredential>(d_localPrincipal, GSS_C_INITIATE);
      cred = (*lock)[d_localPrincipal];
    }
  }

  // see if we can find a context in non-completed state
  if (d_ctx) {
    if (d_ctx->d_state != GssSecContext::GssStateNegotiate) {
      d_error = GSS_CONTEXT_INVALID;
      return false;
    }
  }
  else {
    // make context
    auto lock = s_gss_sec_context.lock();
    (*lock)[d_label] = std::make_shared<GssSecContext>(cred);
    (*lock)[d_label]->d_type = d_type;
    d_ctx = (*lock)[d_label];
    d_ctx->d_state = GssSecContext::GssStateNegotiate;
  }

  recv_tok.length = input.size();
  recv_tok.value = const_cast<void*>(static_cast<const void*>(input.c_str()));

  if (!d_peerPrincipal.empty()) {
    buffer.value = const_cast<void*>(static_cast<const void*>(d_peerPrincipal.c_str()));
    buffer.length = d_peerPrincipal.size();
    maj = gss_import_name(&min, &buffer, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &(d_ctx->d_peer_name));
    if (maj != GSS_S_COMPLETE) {
      processError("gss_import_name", maj, min);
      return false;
    }
  }

  maj = gss_init_sec_context(&min, cred->d_cred, &(d_ctx->d_ctx), d_ctx->d_peer_name, GSS_C_NO_OID, GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG, GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS, &recv_tok, nullptr, &send_tok, &flags, &expires);

  if (send_tok.length > 0) {
    output.assign(static_cast<char*>(send_tok.value), send_tok.length);
    tmp_maj = gss_release_buffer(&tmp_min, &send_tok);
  }

  if (maj == GSS_S_COMPLETE) {
    if (expires > GSS_C_INDEFINITE) {
      d_ctx->d_expires = time(nullptr) + expires;
    }
    else {
      d_ctx->d_expires = -1;
    }
    d_ctx->d_state = GssSecContext::GssStateComplete;
    return true;
  }
  else if (maj != GSS_S_CONTINUE_NEEDED) {
    processError("gss_init_sec_context", maj, min);
  }

  return (maj == GSS_S_CONTINUE_NEEDED);
}

bool GssContext::accept(const std::string& input, std::string& output)
{
  OM_uint32 tmp_maj __attribute__((unused)), tmp_min __attribute__((unused));
  OM_uint32 maj, min;
  gss_buffer_desc recv_tok, send_tok;
  OM_uint32 flags;
  OM_uint32 expires;

  std::shared_ptr<GssCredential> cred;
  if (d_label.empty()) {
    d_error = GSS_CONTEXT_INVALID;
    return false;
  }

  d_type = GSS_CONTEXT_ACCEPT;
  {
    auto lock = s_gss_accept_creds.lock();
    if (lock->find(d_localPrincipal) != lock->end()) {
      cred = (*lock)[d_localPrincipal];
    }
    else {
      (*lock)[d_localPrincipal] = std::make_shared<GssCredential>(d_localPrincipal, GSS_C_ACCEPT);
      cred = (*lock)[d_localPrincipal];
    }
  }

  // see if we can find a context in non-completed state
  if (d_ctx) {
    if (d_ctx->d_state != GssSecContext::GssStateNegotiate) {
      d_error = GSS_CONTEXT_INVALID;
      return false;
    }
  }
  else {
    // make context
    auto lock = s_gss_sec_context.lock();
    (*lock)[d_label] = std::make_shared<GssSecContext>(cred);
    (*lock)[d_label]->d_type = d_type;
    d_ctx = (*lock)[d_label];
    d_ctx->d_state = GssSecContext::GssStateNegotiate;
  }

  recv_tok.length = input.size();
  recv_tok.value = const_cast<void*>(static_cast<const void*>(input.c_str()));

  maj = gss_accept_sec_context(&min, &(d_ctx->d_ctx), cred->d_cred, &recv_tok, GSS_C_NO_CHANNEL_BINDINGS, &(d_ctx->d_peer_name), nullptr, &send_tok, &flags, &expires, nullptr);

  if (send_tok.length > 0) {
    output.assign(static_cast<char*>(send_tok.value), send_tok.length);
    tmp_maj = gss_release_buffer(&tmp_min, &send_tok);
  }

  if (maj == GSS_S_COMPLETE) {
    if (expires > GSS_C_INDEFINITE) {
      d_ctx->d_expires = time(nullptr) + expires;
    }
    else {
      d_ctx->d_expires = -1;
    }
    d_ctx->d_state = GssSecContext::GssStateComplete;
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

  maj = gss_get_mic(&min, d_ctx->d_ctx, GSS_C_QOP_DEFAULT, &recv_tok, &send_tok);

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
  recv_tok.value =  const_cast<void*>(static_cast<const void*>(input.c_str()));
  sign_tok.length = signature.size();
  sign_tok.value =  const_cast<void*>(static_cast<const void*>(signature.c_str()));

  maj = gss_verify_mic(&min, d_ctx->d_ctx, &recv_tok, &sign_tok, nullptr);

  if (maj != GSS_S_COMPLETE) {
    processError("gss_get_mic", maj, min);
  }

  return (maj == GSS_S_COMPLETE);
}

bool GssContext::destroy()
{
  return false;
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

  if (d_ctx->d_peer_name != GSS_C_NO_NAME) {
    maj = gss_display_name(&min, d_ctx->d_peer_name, &value, nullptr);
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

void GssContext::processError(const std::string& method, OM_uint32 maj, OM_uint32 min)
{
  OM_uint32 tmp_min;
  gss_buffer_desc msg;
  OM_uint32 msg_ctx;

  msg_ctx = 0;
  while (1) {
    ostringstream oss;
    gss_display_status(&tmp_min, maj, GSS_C_GSS_CODE, GSS_C_NULL_OID, &msg_ctx, &msg);
    oss << method << ": " << msg.value;
    d_gss_errors.push_back(oss.str());
    if (!msg_ctx)
      break;
  }
  msg_ctx = 0;
  while (1) {
    ostringstream oss;
    gss_display_status(&tmp_min, min, GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &msg);
    oss << method << ": " << msg.value;
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
  mac = tmp_mac;
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
