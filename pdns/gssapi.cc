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
#include "arguments.hh"

#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>

using namespace std;

pthread_mutex_t gss_mutex;

static gss_cred_id_t gss_cred = GSS_C_NO_CREDENTIAL;

// helper
class gss_ctx_s {
public:
  gss_ctx_s() {
    ctx = GSS_C_NO_CONTEXT;
    source = GSS_C_NO_NAME;
    expires = 0;
    inception = time((time_t*)NULL);
    ready = false;
  };

  gss_ctx_s(const gss_ctx_s& rhl) {
    ctx=rhl.ctx;
    source=rhl.source;
    expires=rhl.expires;
    inception=rhl.inception;
    ready=rhl.ready;
  }

  gss_ctx_s& operator=(const gss_ctx_s& rhl) {
    ctx=rhl.ctx;
    source=rhl.source;
    expires=rhl.expires;
    inception=rhl.inception;
    ready=rhl.ready;
    return *this;
  }

  gss_ctx_id_t ctx;
  gss_name_t source;
  time_t inception;
  OM_uint32 expires;
  bool ready;
};

typedef map<string, gss_ctx_s> gss_ctx_map_t;
static gss_ctx_map_t gss_ctx_map;

bool pdns_gssapi_ctx_find(const std::string& label, gss_ctx_s* context, bool ready_only=true);

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

bool pdns_gssapi_match_credential(const std::string& label, const std::string& credential) 
{
  OM_uint32 maj_status, min_status, ign;
  int res;

  // locate context
  gss_ctx_s ctx;
  if (pdns_gssapi_ctx_find(label, &ctx) && (ctx.source != GSS_C_NO_NAME)) {
    gss_buffer_desc value;
    gss_name_t comp;
    value.length = credential.size();
    value.value = (void*)credential.c_str();
    maj_status = gss_import_name(&min_status, &value, (const gss_OID)GSS_C_NO_OID, &comp);

    if (GSS_ERROR(maj_status)) {
      pdns_gssapi_display_status("pdns_gssapi_match_credential", maj_status, min_status);
      return false;
    }

    maj_status = gss_compare_name(&min_status, comp, ctx.source, &res);
    gss_release_name(&ign, &comp);

    if (GSS_ERROR(maj_status)) {
      pdns_gssapi_display_status("pdns_gssapi_match_credential", maj_status, min_status);
      return false;
    }

    return res!=0;
  }

  return false; // no context, no match 
}

bool pdns_gssapi_get_credential(void) {
  OM_uint32 maj_status, min_status;
  gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
  gss_name_t target_name;
  string principal;
  bool retval = true;

  // determine what kind of cred we want...
  principal = ::arg()["gssapi-use-principal"];

  if (principal.empty()) return true; // we fail bit later if no cred is available

  // try to get us a name
  value.length = principal.size();
  value.value = (void*)principal.c_str();

  gss_import_name(&min_status, &value, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &target_name);
  maj_status = gss_acquire_cred(&min_status, target_name, GSS_C_INDEFINITE, GSS_C_NO_OID_SET, GSS_C_ACCEPT, &gss_cred, NULL, NULL);

  if (GSS_ERROR(maj_status)) {
    pdns_gssapi_display_status("gss_acquire_cred", maj_status, min_status);
    retval = false;
  }

  gss_release_name(&min_status, &target_name);

  return retval;
}

void pdns_gssapi_ctx_release(gss_ctx_s* ctx) {
  OM_uint32 maj_status, min_status;

  if (ctx->source)
    gss_release_name(&min_status, &(ctx->source));

  maj_status = gss_delete_sec_context(&min_status, &ctx->ctx, GSS_C_NO_BUFFER);
  if (GSS_ERROR(maj_status))
    pdns_gssapi_display_status("gss_delete_sec_context", maj_status, min_status);
}

bool pdns_gssapi_ctx_find(const std::string& label, gss_ctx_s* context, bool ready_only) {
  OM_uint32 maj_status, min_status, t;
  
  t = time((time_t*)NULL);

   // perform fast cleanup
  for(gss_ctx_map_t::iterator i = gss_ctx_map.begin(); i != gss_ctx_map.end(); i++) {
    if ((i->second.inception + i->second.expires) < t) {
      pdns_gssapi_ctx_release(&(i->second));
      gss_ctx_map.erase(i++);
    }
  }

  if (gss_ctx_map.find(label) != gss_ctx_map.end()) {
    gss_ctx_s ctx = gss_ctx_map[label];
    if (ready_only && ctx.ready == false) return false;
 
    maj_status = gss_context_time(&min_status, ctx.ctx, &t); // re-check expiration
    if (maj_status != GSS_S_COMPLETE) {
       // invalidate
       gss_release_name(&min_status, &(ctx.source));
       gss_ctx_map.erase(label);
       return false;
    }
    if (context) { *context = ctx; }
    return true;
  }

  return false;
}

int pdns_gssapi_accept_ctx(const std::string& label, const std::string& input, std::string& output) {
  Lock l(&gss_mutex);

  OM_uint32 maj_status, min_status, flags;
  gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
  int ret=0;
  gss_ctx_s ctx;
   
  if (gss_cred == GSS_C_NO_CREDENTIAL && !pdns_gssapi_get_credential()) {
    return PDNS_GSSAPI_BADKEY;
  }

  // see if we have existing context
  pdns_gssapi_ctx_find(label, &ctx); // return value is irrelevant. 

  recv_tok.length = input.size();
  recv_tok.value = (void*)input.c_str();
  maj_status = gss_accept_sec_context(&min_status, &(ctx.ctx), gss_cred, &recv_tok, GSS_C_NO_CHANNEL_BINDINGS, &ctx.source, NULL, &send_tok, &flags, &(ctx.expires), NULL);

  if (GSS_ERROR(maj_status)) {
    pdns_gssapi_display_status("accept_context", maj_status, min_status);
  }

  if (send_tok.length > 0) {
    output.assign((const char*)send_tok.value, send_tok.length);
    gss_release_buffer(&min_status, &send_tok);
  };

  if (GSS_ERROR(maj_status)) {
    pdns_gssapi_ctx_release(&ctx);
    gss_ctx_map.erase(label);
    ret = PDNS_GSSAPI_BADKEY;
  }

  if ((maj_status == GSS_S_COMPLETE) &&
      (!(flags & GSS_C_MUTUAL_FLAG))) {
    // sorry, unacceptable, peer needs to auth too
    L<<Logger::Error<<"GSS-API: accept_context: mutual authentication required but peer did not authenticate itself"<<endl;
    maj_status = GSS_S_DEFECTIVE_CREDENTIAL; // anything that makes it fail 
    pdns_gssapi_ctx_release(&ctx);
    gss_ctx_map.erase(label); 
    ret = PDNS_GSSAPI_BADKEY;
  } else if (!GSS_ERROR(maj_status)) {
    if (maj_status == GSS_S_COMPLETE) {
      gss_display_name(&min_status, ctx.source, &value, NULL);
      L<<Logger::Info<<"GSS-API: accept_context: handshake completed with "<< (char*)value.value<<endl;
      gss_release_buffer(&min_status,&value);
      ctx.ready = true;
      std::swap(gss_ctx_map[label], ctx);
    } else if (maj_status == GSS_S_CONTINUE_NEEDED) {
      ret = PDNS_GSSAPI_CONTINUE;
      std::swap(gss_ctx_map[label], ctx);
    } else {
      ret = PDNS_GSSAPI_BADKEY; // just in case
    }
  }

  return ret;
}

bool pdns_gssapi_delete_ctx(const std::string& label, const std::string& input, std::string& output) {
  Lock l(&gss_mutex);
  gss_ctx_s ctx;

  if (pdns_gssapi_ctx_find(label, &ctx)) {
    ctx.expires = 0; // ensures it gets deleted next time round
    return true;
  }

  return false;
}

bool pdns_gssapi_sign(const std::string& label, const std::string& input, std::string& output) {
  Lock l(&gss_mutex);

  OM_uint32 maj_status, min_status;
  gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
  gss_ctx_s ctx;

  if (pdns_gssapi_ctx_find(label, &ctx)) {
    recv_tok.length = input.size();
    recv_tok.value = (void*)input.c_str();

    maj_status = gss_get_mic(&min_status, ctx.ctx, GSS_C_QOP_DEFAULT, &recv_tok, &send_tok);
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
  gss_ctx_s ctx;

  if (pdns_gssapi_ctx_find(label, &ctx)) {
    recv_tok.length = input.size();
    recv_tok.value = (void*)input.c_str();
    sign_tok.length = token.size();
    sign_tok.value = (void*)token.c_str();

    maj_status = gss_verify_mic(&min_status, ctx.ctx, &recv_tok, &sign_tok, NULL);

    if (GSS_ERROR(maj_status)) {
      pdns_gssapi_display_status("pdns_gssapi_verify", maj_status, min_status);
    }

    return (maj_status == GSS_S_COMPLETE);
  } else {
    L<<Logger::Error<<"GSS verification request with label " << label << ", but no context found" << endl;
  }

  return false;
}
