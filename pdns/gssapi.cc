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

  // try to get us a name
  value.length = strlen("DNS/labra01.unit.test@UNIT.TEST");
  value.value = (void*)"DNS/labra01.unit.test@UNIT.TEST";

  gss_import_name(&min_status, &value, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &target_name);
  gss_acquire_cred(&min_status, target_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &gss_cred, NULL, NULL);
  gss_release_name(&min_status, &target_name);

  return true;
}

gss_ctx_id_t pdns_gssapi_find_ctx(const std::string& label) {
  Lock l(&gss_mutex);

  if (gss_ctx_map.find(label) != gss_ctx_map.end()) {
    return gss_ctx_map[label];
  }

  return GSS_C_NO_CONTEXT;
}

OM_uint32 pdns_gssapi_accept_ctx(const std::string& label, const std::string& input, std::string& output) {
  Lock l(&gss_mutex);

  OM_uint32 maj_status, min_status;
  gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
//  gss_name_t source_name;

  if (gss_cred == GSS_C_NO_CREDENTIAL) pdns_gssapi_get_credential(); 
  
  recv_tok.length = input.size();
  recv_tok.value = (void*)input.c_str();
  maj_status = gss_accept_sec_context(&min_status, &ctx, gss_cred, &recv_tok, GSS_C_NO_CHANNEL_BINDINGS, NULL, NULL, &send_tok, NULL, NULL, NULL);

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

  if (maj_status & GSS_S_COMPLETE) {
     gss_ctx_map[label] = ctx;
  }

  return maj_status;
}

bool pdns_gssapi_delete_ctx(const std::string& label, const std::string& input, std::string& output) {
  Lock l(&gss_mutex);

  OM_uint32 maj_status, min_status;
  gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;

  if (gss_ctx_map.find(label) != gss_ctx_map.end()) {
    gss_ctx_id_t ctx = gss_ctx_map[label];
    gss_ctx_map.erase(label);
    gss_delete_sec_context(&min_status, &ctx, &send_tok);
    if (send_tok.length > 0) {
      output.assign((const char*)send_tok.value, send_tok.length);
      gss_release_buffer(&min_status, &send_tok);
    }
    return true;
  }

  return false;
}
