// $Id$

#include <string>
#include <map>
#include <fstream>

#include <oci.h>

using namespace std;

static const int kForwardQuery            = 0;
static const int kForwardQueryByZone      = 1;
static const int kForwardAnyQuery         = 2;
static const int kForwardWildcardQuery    = 3;
static const int kForwardWildcardAnyQuery = 4;
static const int kListQuery               = 5;
static const int kNumQueries              = 6;

class OracleException
{
   public:
      
      OracleException()
      {
         mReason = "Unspecified";
      }
      
      OracleException(string theReason)
      {
         mReason = theReason;
      }

      OracleException(OCIError *theErrorHandle)
      {
         mReason = "ORA-UNKNOWN";

         if (theErrorHandle != NULL)
         {
            text  msg[512];
            sb4   errcode = 0;
   
            memset((void *) msg, (int)'\0', (size_t)512);
   
            OCIErrorGet((dvoid *) theErrorHandle,1, NULL, &errcode, msg, sizeof(msg), OCI_HTYPE_ERROR);
            if (errcode)
            {
              char *p = (char*) msg;
               while (*p++ != 0x00) {
        	  if (*p == '\n' || *p == '\r') {
        	    *p = ';';
        	  }
        	}
        	
        	mReason = (char*) msg;
            }
         }
      }

      string Reason()
      {
         return mReason;
      }
      
      string mReason;
};

class OracleBackend : public DNSBackend
{
   public:
      
      OracleBackend(const string &suffix="");
      virtual ~OracleBackend();
      
      void lookup(const QType &, const string &qdomain, DNSPacket *p=0, int zoneId=-1);
      bool list(const string &target, int domain_id);
      bool get(DNSResourceRecord &r);

      
      
   private:

      bool mUpperCase;
      bool mDebugQueries;
      bool mTimeQueries;
      string mTimeQueriesFile;
      fstream mTimeQueriesStream;
      
      void Cleanup();
      
      OCIEnv    *mEnvironmentHandle;
      OCIError  *mErrorHandle;
      OCISvcCtx *mServiceContextHandle;
      OCIStmt   *mStatementHandles[10];
      
      const char* mQueries[kNumQueries];

      int mActiveQuery;

      dsword mQueryResult;

      char mQueryName[256];
      char mQueryContent[256];
      char mQueryType[256];
      int  mQueryId;

      char mResultContent[256];
      int  mResultTTL;
      int  mResultPriority;
      char mResultType[256];
      int  mResultDomainId;
      int  mResultChangeDate;
      char mResultName[256];

      sb2  mResultContentIndicator;
      sb2  mResultTTLIndicator;
      sb2  mResultPriorityIndicator;
      sb2  mResultTypeIndicator;
      sb2  mResultDomainIdIndicator;
      sb2  mResultChangeDateIndicator;
      sb2  mResultNameIndicator;
};
