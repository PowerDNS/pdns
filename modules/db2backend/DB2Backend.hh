// $Id$

#ifndef DB2BACKEND_HH
#define DB2BACKEND_HH

#include <string>
#include <map>

#include "pdns/namespaces.hh"

#include <sqlcli1.h>

class DB2Backend : public DNSBackend
{
   public:

      DB2Backend(const string &suffix = "");
      ~DB2Backend();

      void lookup(const QType &, const string &qdomain, DNSPacket *p = 0, int zoneId = -1);
      bool list(int inZoneId);
      bool get(DNSResourceRecord& outRecord);
      bool getSOA(const string &name, SOAData &soadata);

      static DNSBackend *maker();

   private:

      void Cleanup();

   private:

      // Handles
      SQLHANDLE  mConnection;
      SQLHANDLE  mEnvironment;
      SQLHANDLE  mStatements[6];
      bool       mStatementStates[6];
      SQLHANDLE  mSoaStatement;
      SQLHANDLE  mCurrentStatement;

      // Parameters
      char mParamName[256];
      char mParamNameLength;
      char mParamType[256];
      char mParamTypeLength;
      int  mParamZoneId;
      int  mParamZoneIdLength;

      // Columns
      char        mResultContent[256];
      SQLINTEGER  mResultContentIndicator;
      int         mResultTimeToLive;
      SQLINTEGER  mResultTimeToLiveIndicator;
      int         mResultPriority;
      SQLINTEGER  mResultPriorityIndicator;
      char        mResultType[256];
      SQLINTEGER  mResultTypeIndicator;
      int         mResultZoneId;
      SQLINTEGER  mResultZoneIdIndicator;
      int         mResultChangeDate;
      SQLINTEGER  mResultChangeDateIndicator;
      char        mResultName[256];
      SQLINTEGER  mResultNameIndicator;

      // SOA Parameters
      char       mSoaParamName[256];

      // SOA Result
      int        mSoaResultZoneId;
      SQLINTEGER mSoaResultZoneIdIndicator;
      char       mSoaResultNameserver[256];
      SQLINTEGER mSoaResultNameserverIndicator;
      char       mSoaResultHostmaster[256];
      SQLINTEGER mSoaResultHostmasterIndicator;
      int        mSoaResultSerial;
      SQLINTEGER mSoaResultSerialIndicator;
};

#endif /* DB2BACKEND_HH */
