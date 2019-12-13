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
#pragma once

#ifdef ENABLE_GSS_TSIG
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>
#endif

//! Generic errors
enum GssContextError {
  GSS_CONTEXT_NO_ERROR,
  GSS_CONTEXT_UNSUPPORTED,
  GSS_CONTEXT_NOT_FOUND,
  GSS_CONTEXT_NOT_INITIALIZED,
  GSS_CONTEXT_INVALID,
  GSS_CONTEXT_EXPIRED,
  GSS_CONTEXT_ALREADY_INITIALIZED
};

//! GSS context types
enum GssContextType {
  GSS_CONTEXT_NONE,
  GSS_CONTEXT_INIT,
  GSS_CONTEXT_ACCEPT
};

class GssSecContext;

/*! Class for representing GSS names, such as host/host.domain.com@REALM.
*/
class GssName {
public:
  //! Initialize to empty name
  GssName() {
    setName("");
  };

  //! Initialize using specific name
  GssName(const std::string& name) {
    setName(name);
  };

  //! Parse name into native representation
  bool setName(const std::string& name) {
#ifdef ENABLE_GSS_TSIG
    gss_buffer_desc buffer;
    d_name = GSS_C_NO_NAME;

    if (!name.empty()) {
      buffer.length = name.size();
      buffer.value = (void*)name.c_str();
      d_maj = gss_import_name(&d_min, &buffer, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &d_name);
      return d_maj == GSS_S_COMPLETE;
    }

    return true;
#endif
    return false;
  };

  ~GssName() {
#ifdef ENABLE_GSS_TSIG
     if (d_name != GSS_C_NO_NAME)
       gss_release_name(&d_min, &d_name);
#endif
  };

  //! Compare two Gss Names, if no gss support is compiled in, returns false always
  //! This is not necessarily same as string comparison between two non-parsed names
  bool operator==(const GssName& rhs) {
#ifdef ENABLE_GSS_TSIG
    OM_uint32 maj,min;
    int result;
    maj = gss_compare_name(&min, d_name, rhs.d_name, &result);
    return (maj == GSS_S_COMPLETE && result != 0);
#endif
    return false;
  }

  //! Compare two Gss Names, if no gss support is compiled in, returns false always
  //! This is not necessarily same as string comparison between two non-parsed names
  bool match(const std::string& name) {
#ifdef ENABLE_GSS_TSIG
    OM_uint32 maj,min;
    int result;
    gss_name_t comp;
    gss_buffer_desc buffer;
    buffer.length = name.size();
    buffer.value = (void*)name.c_str();
    maj = gss_import_name(&min, &buffer, (gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME, &comp);
    if (maj != GSS_S_COMPLETE)
      throw PDNSException("Could not import " + name + ": " + std::to_string(maj) + string(",") + std::to_string(min));
    // do comparison
    maj = gss_compare_name(&min, d_name, comp, &result);
    gss_release_name(&min, &comp);
    return (maj == GSS_S_COMPLETE && result != 0);
#else
   return false;
#endif
  };

  //! Check if GSS name was parsed successfully.
  bool valid() {
#ifdef ENABLE_GSS_TSIG
    return d_maj == GSS_S_COMPLETE;
#else
    return false;
#endif
  }
private:
#ifdef ENABLE_GSS_TSIG
  OM_uint32 d_maj,d_min;
  gss_name_t d_name;
#endif
};

class GssContext {
public:
  static bool supported(); //<! Returns true if GSS is supported in the first place
  GssContext(); //<! Construct new GSS context with random name
  GssContext(const DNSName& label); //<! Create or open existing named context

  void setLocalPrincipal(const std::string& name); //<! Set our gss name
  bool getLocalPrincipal(std::string& name); //<! Get our name
  void setPeerPrincipal(const std::string& name); //<! Set remote name (do not use after negotiation)
  bool getPeerPrincipal(std::string &name); //<! Return remote name, returns actual name after negotiation

  void generateLabel(const std::string& suffix); //<! Generate random context name using suffix (such as mydomain.com)
  void setLabel(const DNSName& label); //<! Set context name to this label
  const DNSName& getLabel() { return d_label; } //<! Return context name

  bool init(const std::string &input, std::string& output); //<! Perform GSS Initiate Security Context handshake
  bool accept(const std::string &input, std::string& output); //<! Perform GSS Accept Security Context handshake
  bool destroy(); //<! Release the cached context
  bool expired(); //<! Check if context is expired
  bool valid(); //<! Check if context is valid

  bool sign(const std::string &input, std::string& output); //<! Sign something using gss
  bool verify(const std::string &input, const std::string &signature); //<! Validate gss signature with something

  GssContextError getError(); //<! Get error
  const std::vector<std::string> getErrorStrings() { return d_gss_errors; } //<! Get native error texts
 private:
  void release(); //<! Release context
  void initialize(); //<! Initialize context
#ifdef ENABLE_GSS_TSIG
  void processError(const string& method, OM_uint32 maj, OM_uint32 min); //<! Process and fill error text vector
#endif
  DNSName d_label; //<! Context name
  std::string d_peerPrincipal; //<! Remote name
  std::string d_localPrincipal; //<! Our name
  GssContextError d_error; //<! Context error
  GssContextType d_type; //<! Context type
  std::vector<std::string> d_gss_errors; //<! Native error string(s)
  boost::shared_ptr<GssSecContext> d_ctx; //<! Attached security context
};

bool gss_add_signature(const DNSName& context, const std::string& message, std::string& mac); //<! Create signature
bool gss_verify_signature(const DNSName& context, const std::string& message, const std::string& mac); //<! Validate signature
