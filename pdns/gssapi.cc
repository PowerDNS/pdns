#include <map>
#include <string>
#include "config.h"
#include "namespaces.hh"
#include "dns.hh"
#include "dnsparser.hh"
#include "dnspacket.hh"
#include "dnsrecords.hh"
#include "tkey.hh"
#include "logger.hh"
#include "lock.hh"
#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>

using namespace std;

typedef map<string, gss_ctx_id_t> gss_ctx_map_t;
pthread_mutex_t gss_mutex;

static gss_ctx_map_t gss_ctx_map;
static gss_cred_id_t gss_cred = GSS_C_NO_CREDENTIAL;

static void pdns_gssapi_display_status_1(const char *m, OM_uint32 code, int type)
{
     OM_uint32 min_stat;
     gss_buffer_desc msg;
     OM_uint32 msg_ctx;

     msg_ctx = 0;
     while (1) {
          gss_display_status(&min_stat, code,
                                       type, GSS_C_NULL_OID,
                                       &msg_ctx, &msg);
          std::string smsg;
          smsg.assign((char*)msg.value, msg.length);
          L<<Logger::Error<<"GSS-API error "<<m<<": "<<smsg<<endl;
          (void) gss_release_buffer(&min_stat, &msg);

          if (!msg_ctx)
               break;
     }
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 *      msg             a string to be displayed with the message
 *      maj_stat        the GSS-API major status code
 *      min_stat        the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
static void pdns_gssapi_display_status(const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
     pdns_gssapi_display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
     pdns_gssapi_display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

bool pdns_gssapi_get_credential(void) {
  OM_uint32 maj_status, min_status;
  gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
  gss_name_t target_name;
  bool retval = true;

  // try to get us a name
  value.length = strlen("DNS/");
  value.value = (void*)"DNS/";

  gss_import_name(&min_status, &value, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &target_name);
  maj_status = gss_acquire_cred(&min_status, target_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &gss_cred, NULL, NULL);

  if (GSS_ERROR(maj_status)) {
    pdns_gssapi_display_status("gss_acquire_cred", maj_status, min_status);
    retval = false;
  }

  gss_release_name(&min_status, &target_name);

  return retval;
}

gss_ctx_id_t pdns_gssapi_find_ctx_real(const std::string& label) {
  OM_uint32 maj_status, min_status, t;

   //FIXME: reap any expired credentials first to clean up

  if (gss_ctx_map.find(label) != gss_ctx_map.end()) {
    gss_ctx_id_t ctx = gss_ctx_map[label];
    maj_status = gss_context_time(&min_status, ctx, &t);
    if (maj_status != GSS_S_COMPLETE) {
       // invalidate
       gss_ctx_map.erase(label);
       return GSS_C_NO_CONTEXT;
    }
    return ctx;
  }

  return GSS_C_NO_CONTEXT;
}

gss_ctx_id_t pdns_gssapi_find_ctx(const std::string& label) {
  Lock l(&gss_mutex);

  return pdns_gssapi_find_ctx_real(label);
}

OM_uint32 pdns_gssapi_accept_ctx(const std::string& label, const std::string& input, std::string& output) {
  Lock l(&gss_mutex);

  OM_uint32 maj_status, min_status, flags;
  gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_name_t source_name;

/*  if (gss_cred == GSS_C_NO_CREDENTIAL && !pdns_gssapi_get_credential()) {
    return GSS_S_DEFECTIVE_CREDENTIAL;
  } */

  // FIXME: Credential hunting, context resumption

  recv_tok.length = input.size();
  recv_tok.value = (void*)input.c_str();
  maj_status = gss_accept_sec_context(&min_status, &ctx, gss_cred, &recv_tok, GSS_C_NO_CHANNEL_BINDINGS, &source_name, NULL, &send_tok, &flags, NULL, NULL);

  if (GSS_ERROR(maj_status)) {
    pdns_gssapi_display_status("accept_context", maj_status, min_status);
  }

  if (send_tok.length > 0) {
    output.assign((const char*)send_tok.value, send_tok.length);
    gss_release_buffer(&min_status, &send_tok);
  };

  if (GSS_ERROR(maj_status)) {
    if (ctx != GSS_C_NO_CONTEXT) {
      gss_delete_sec_context(&min_status,
                             &ctx,
                             GSS_C_NO_BUFFER);
      }
  }

  if ((maj_status == GSS_S_COMPLETE) &&
      (!(flags & GSS_C_MUTUAL_FLAG))) {
    // sorry, unacceptable, peer needs to auth too
    if (ctx != GSS_C_NO_CONTEXT) {
      gss_delete_sec_context(&min_status,
                             &ctx,
                             GSS_C_NO_BUFFER);
    }
    L<<Logger::Error<<"GSS-API: accept_context: mutual authentication required but peer did not authenticate itself"<<endl;
    maj_status = GSS_S_DEFECTIVE_CREDENTIAL; // anything that makes it fail 
  } else if (maj_status == GSS_S_COMPLETE) {
    gss_display_name(&min_status, source_name, &value, NULL);
    L<<Logger::Info<<"GSS-API: accept_context: handshake completed with "<< (char*)value.value<<endl;
    gss_release_buffer(&min_status,&value);
    gss_release_name(&min_status, &source_name);
    gss_ctx_map[label] = ctx;
  }

  return maj_status;
}

bool pdns_gssapi_delete_ctx(const std::string& label, const std::string& input, std::string& output) {
  Lock l(&gss_mutex);

  OM_uint32 maj_status, min_status;
  gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
  gss_ctx_id_t ctx = pdns_gssapi_find_ctx_real(label);

  if (ctx != GSS_C_NO_CONTEXT) {
    gss_ctx_map.erase(label); //FIXME: should really be MARKED for deletion
    maj_status = gss_delete_sec_context(&min_status, &ctx, &send_tok);
    if (GSS_ERROR(maj_status))
      pdns_gssapi_display_status("gss_delete_sec_context", maj_status, min_status);
    if (send_tok.length > 0) {
      output.assign((const char*)send_tok.value, send_tok.length);
      gss_release_buffer(&min_status, &send_tok);
    }
    return true;
  }

  return false;
}

bool pdns_gssapi_sign(const std::string& label, const std::string& input, std::string& output) {
  Lock l(&gss_mutex);

  OM_uint32 maj_status, min_status;
  gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
  gss_ctx_id_t ctx = pdns_gssapi_find_ctx_real(label);

  if (ctx != GSS_C_NO_CONTEXT) {
    recv_tok.length = input.size();
    recv_tok.value = (void*)input.c_str();

    maj_status = gss_get_mic(&min_status, ctx, GSS_C_QOP_DEFAULT, &recv_tok, &send_tok);
    if (GSS_ERROR(maj_status)) {
      pdns_gssapi_display_status("pdns_gssapi_sign", maj_status, min_status);
    }

    if (send_tok.length>0) {
      output.assign((const char*)send_tok.value, send_tok.length);
      gss_release_buffer(&min_status, &send_tok);
    }

    return (maj_status == GSS_S_COMPLETE);
  } else {
    L<<Logger::Error<<"GSS signing request with label " << label << ", but no context found" << endl;
  }

  return false;
}

bool pdns_gssapi_verify(const std::string& label, const std::string& input, const std::string& token) {
  Lock l(&gss_mutex);

  OM_uint32 maj_status, min_status;
  gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc sign_tok = GSS_C_EMPTY_BUFFER;
  gss_ctx_id_t ctx = pdns_gssapi_find_ctx_real(label);

  if (ctx != GSS_C_NO_CONTEXT) {
    recv_tok.length = input.size();
    recv_tok.value = (void*)input.c_str();
    sign_tok.length = token.size();
    sign_tok.value = (void*)token.c_str();

    maj_status = gss_verify_mic(&min_status, ctx, &recv_tok, &sign_tok, NULL);

    if (GSS_ERROR(maj_status)) {
      pdns_gssapi_display_status("pdns_gssapi_verify", maj_status, min_status);
    }

    return (maj_status == GSS_S_COMPLETE);
  } else {
    L<<Logger::Error<<"GSS verification request with label " << label << ", but no context found" << endl;
  }

  return false;
}
