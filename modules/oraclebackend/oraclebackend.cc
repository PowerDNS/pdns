// $Id: oraclebackend.cc,v 1.1 2002/11/27 15:35:52 ahu Exp $

#include <string>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/time.h>

using namespace std;

#include "dns.hh"
#include "dnsbackend.hh"
#include "ahuexception.hh"
#include "logger.hh"
#include "oraclebackend.hh"

#include <oci.h>

static const char *kDefaultQueries[kNumQueries] =
{
  // ForwardQuery
  "select content, TimeToLive, Priority, type, ZoneId, nvl(ChangeDate,0) from Records where name = :name and type = :type",
  
  // ForwardQueryByZone
  
  "select content, TimeToLive, Priority, type, ZoneId, nvl(ChangeDate,0) from records where name = :name and type = :type and ZoneId = :id",

  // ForwardAnyQuery
  
  "select content, TimeToLive, Priority, type, ZoneId, nvl(ChangeDate,0) from records where name = :name",

  // ForwardWildcardQuery

  "select content, TimeToLive, Priority, type, ZoneId, nvl(ChangeDate,0) from records where name like :name and type = :type",

  // ForwardWildcardAnyQuery
  "select content, TimeToLive, Priority, type, ZoneId, nvl(ChangeDate,0) from records where name like :name",

  // ListQuery
  "select content, TimeToLive, Priority, type, ZoneId, nvl(ChangeDate, 0), name from records where ZoneId = :id"
};

static const char* kModuleId = "[OracleBackend] ";

OracleBackend::OracleBackend(const string &suffix)
{
   setArgPrefix(string("oracle")+suffix);
   dsword err;

   if (!getArg("home").empty() && setenv("ORACLE_HOME", getArg("home").c_str(), 1) == -1) {
      throw OracleException("Cannot set ORACLE_HOME");
   }

   if (!getArg("sid").empty() && setenv("ORACLE_SID", getArg("sid").c_str(), 1) == -1) {
      throw OracleException("Cannot set ORACLE_SID");
   }

   //
   // Initialize everything in a known state
   //

   mEnvironmentHandle = NULL;
   mErrorHandle = NULL;
   mServiceContextHandle = NULL;
   
   for (int i = 0; i < kNumQueries; i++) {
     mStatementHandles[i] = NULL;
   }

   // Process configuration options
   
   mQueries[0] = getArg("forward-query").c_str();
   mQueries[1] = getArg("forward-query-by-zone").c_str();
   mQueries[2] = getArg("forward-any-query").c_str();
   mQueries[3] = getArg("forward-wildcard-query").c_str();
   mQueries[4] = getArg("forward-wildcard-any-query").c_str();
   mQueries[5] = getArg("list-query").c_str();

   mUpperCase = mustDo("uppercase");
   mDebugQueries = mustDo("debug-queries");
   mTimeQueries = mustDo("time-queries");

   if (mTimeQueries == true) {
      mTimeQueriesFile = getArg("time-queries");
      L << Logger::Error << kModuleId << "Logging SQL query statistics to: " << mTimeQueriesFile << endl;
      mTimeQueriesStream.open(mTimeQueriesFile.c_str(), ios::out | ios::app);
   }
   
   try
   {      
      // Initialize and create the environment
  
      err = OCIInitialize(OCI_THREADED, 0,  NULL, NULL, NULL);
      if (err) {
	 throw OracleException("OCIInitialize");
      }

      err = OCIEnvInit(&mEnvironmentHandle, OCI_DEFAULT, 0, 0);
      if (err) {
	 throw OracleException("OCIEnvInit");
      }
  
      // Allocate an error handle
      
      err = OCIHandleAlloc(mEnvironmentHandle, (dvoid**) &mErrorHandle, OCI_HTYPE_ERROR, 0, NULL);
      if (err) {
	 throw OracleException("OCIHandleAlloc");
      }
  
      // Logon to the database
      
      const char *username = getArg("username").c_str();
      const char *password = getArg("password").c_str();
      const char *database = getArg("database").c_str();

      err = OCILogon(mEnvironmentHandle, mErrorHandle, &mServiceContextHandle, (OraText*) username, strlen(username),
		     (OraText*) password,  strlen(password), (OraText*) database, strlen(database));
      
      if (err) {
	 throw OracleException(mErrorHandle);
      }

      // Allocate the statement handles, and prepare the statements

      for (int i = 0; i < kNumQueries; i++)
      {
	 err = OCIHandleAlloc(mEnvironmentHandle, (dvoid **) &mStatementHandles[i], OCI_HTYPE_STMT, 0, NULL);
	 
	 if (err) {
	    throw OracleException(mErrorHandle);
	 }

	 err = OCIStmtPrepare(mStatementHandles[i], mErrorHandle, (text*) mQueries[i], strlen(mQueries[i]),
           OCI_NTV_SYNTAX, OCI_DEFAULT);

	 if (err) {
	    throw OracleException(mErrorHandle);
	 }

	 // Bind query arguments
	 OCIBind *theBindHandle = NULL;

         // Only the kListQuery and kForwardQueryByZone have an :id field

	 if (i == kListQuery || i == kForwardQueryByZone)
	 {
	    err = OCIBindByName(mStatementHandles[i], &theBindHandle, mErrorHandle, (OraText*) ":id", strlen(":id"),
				(ub1 *) &mQueryId, sizeof(mQueryId), SQLT_INT, NULL, NULL, 0, 0, NULL, OCI_DEFAULT);
	    
	    if (err) {
	       throw OracleException(mErrorHandle);
	    }	    
	 }

         // For all the other queries, except for kList Query we have more complex bindings

	 if (i != kListQuery)
	 {
            // All queries have a name: field.

	    if (i < kListQuery)
	    {
	       err = OCIBindByName(mStatementHandles[i], &theBindHandle, mErrorHandle, (OraText*) ":name", strlen(":name"),
				   (ub1 *) mQueryName, sizeof(mQueryName), SQLT_STR, NULL, NULL, 0, 0, NULL, OCI_DEFAULT);
	       
	       if (err) {
		  throw OracleException(mErrorHandle);
	       }
	    }
	    
            // Only these queries have a type: field

	    if (i == kForwardQuery || i == kForwardQueryByZone || i == kForwardWildcardQuery )
	    {
	       err = OCIBindByName(mStatementHandles[i], &theBindHandle, mErrorHandle, (OraText*) ":type", strlen(":type"),
				   (ub1 *) mQueryType, sizeof(mQueryType), SQLT_STR, NULL, NULL, 0, 0, NULL, OCI_DEFAULT);
	       
	       if (err) {
		  throw OracleException(mErrorHandle);
	       }	    
	    }
	 }
	 
	 // Define the output
	 OCIDefine *theDefineHandle;

	 mResultContentIndicator = mResultTTLIndicator = mResultPriorityIndicator = mResultTypeIndicator
           = mResultDomainIdIndicator = mResultChangeDateIndicator = 0;

	 theDefineHandle = NULL; 
	 err = OCIDefineByPos(mStatementHandles[i], &theDefineHandle, mErrorHandle, 1, mResultContent,
           sizeof(mResultContent) - 1, SQLT_STR, (dvoid*) &mResultContentIndicator, NULL, NULL, OCI_DEFAULT);
	 
	 if (err) {
	    throw OracleException(mErrorHandle);
	 }

	 theDefineHandle = NULL;
	 err = OCIDefineByPos(mStatementHandles[i], &theDefineHandle, mErrorHandle, 2, &mResultTTL,
           sizeof(mResultTTL), SQLT_INT, (dvoid*) &mResultTTLIndicator, NULL, NULL, OCI_DEFAULT);
	 
	 if (err) {
	   throw OracleException(mErrorHandle);
	 }
	 theDefineHandle = NULL;
	 err = OCIDefineByPos(mStatementHandles[i], &theDefineHandle, mErrorHandle, 3, &mResultPriority,
           sizeof(mResultPriority), SQLT_INT, (dvoid*) &mResultPriorityIndicator, NULL, NULL, OCI_DEFAULT);
	 
	 if (err) {
	    throw OracleException(mErrorHandle);
	 }
	 
	 theDefineHandle = NULL;
	 err = OCIDefineByPos(mStatementHandles[i], &theDefineHandle, mErrorHandle, 4, mResultType,
           sizeof(mResultType) - 1, SQLT_STR, (dvoid*) &mResultTypeIndicator, NULL, NULL, OCI_DEFAULT);
	 
	 if (err) {
	    throw OracleException(mErrorHandle);
	 }

	 theDefineHandle = NULL;
	 err = OCIDefineByPos(mStatementHandles[i], &theDefineHandle, mErrorHandle, 5, &mResultDomainId,
           sizeof(mResultDomainId), SQLT_INT, (dvoid*) &mResultDomainIdIndicator, NULL, NULL, OCI_DEFAULT);
	 
	 if (err) {
	    throw OracleException(mErrorHandle);
	 }
	 
	 theDefineHandle = NULL;
	 err = OCIDefineByPos(mStatementHandles[i], &theDefineHandle, mErrorHandle, 6, &mResultChangeDate,
           sizeof(mResultChangeDate), SQLT_INT, (dvoid*) &mResultChangeDateIndicator, NULL, NULL, OCI_DEFAULT);
	 
	 if (err) {
	    throw OracleException(mErrorHandle);
	 }

	 if (i == kListQuery)
	 {
	    theDefineHandle = NULL; 
	    err = OCIDefineByPos(mStatementHandles[i], &theDefineHandle, mErrorHandle, 7, mResultName,
              sizeof(mResultName) - 1, SQLT_STR, (dvoid*) &mResultNameIndicator, NULL, NULL, OCI_DEFAULT);
	    
	    if (err) {
	       throw OracleException(mErrorHandle);
	    }
	 }
      }      

   }
   
   catch (OracleException &theException)
   {
     L << Logger::Error << kModuleId << "Connection to database failed: " << theException.Reason() << endl;
     //     Cleanup();
     throw AhuException("Unable to create a connection: " + theException.Reason());
   }
   
   L << Logger::Warning << kModuleId << "Oracle Backend up and running" << endl;
}

OracleBackend::~OracleBackend()
{
  L << Logger::Warning << kModuleId << "Destructing Oracle Backend" << endl;
  Cleanup();
}

void OracleBackend::lookup(const QType &qtype,const string &qname, DNSPacket *pkt_p, int zoneId)
{
   //
   // Choose the right query
   //

   int theQueryType = -1;

   if (qname[0] == '%') {
     if (qtype.getCode() == 255) {
       theQueryType = kForwardWildcardAnyQuery;
     } else {
       theQueryType = kForwardWildcardQuery;
     }
   } else {
     if (qtype.getCode() == 255) {
       theQueryType = kForwardAnyQuery;
     } else {
       if (zoneId != -1) {
	 theQueryType = kForwardQueryByZone;
       } else {
	 theQueryType = kForwardQuery;
       }
     }
   }


   // Fill in the correct query parameters
   
   if (mDebugQueries) {
      printf(">>> executing query: %s\n", mQueries[theQueryType]);
   }

   switch (theQueryType)
   {
      case kForwardQuery:
      case kForwardWildcardQuery:
	 strncpy(mQueryName, qname.c_str(), sizeof(mQueryName));
	 strncpy(mQueryType, qtype.getName().c_str(), sizeof(mQueryType));
         if (mDebugQueries) {
            printf(">>> :name = '%s' :type = '%s'\n", mQueryName, mQueryType);
         }
	 break;

      case kForwardQueryByZone:
	 strncpy(mQueryName, qname.c_str(), sizeof(mQueryName));
	 strncpy(mQueryType, qtype.getName().c_str(), sizeof(mQueryType));	 
	 mQueryId = zoneId;
         if (mDebugQueries) {
            printf(">>> :name = '%s' :type = '%s' :id = '%d'\n", mQueryName, mQueryType, mQueryId);
         }
	 break;

      case kForwardAnyQuery:
      case kForwardWildcardAnyQuery:
	 strncpy(mQueryName, qname.c_str(), sizeof(mQueryName));
         if (mDebugQueries) {
            printf(">>> :name = '%s'\n", mQueryName);
         }
	 break;

   }

   if(mUpperCase == true) {
      char *p = mQueryName;
      while (*p != 0x00) {
	 *p++ = std::toupper(*p);
      }
   }
   
   // Execute the query

   struct timeval theStartTime;

   if (mTimeQueries == true) {
      gettimeofday(&theStartTime, NULL);
   }

   try
   {      
      mActiveQuery = theQueryType;
   
      mQueryResult = OCIStmtExecute(mServiceContextHandle, mStatementHandles[theQueryType], mErrorHandle, 1, 0,
        (OCISnapshot *)NULL, (OCISnapshot*) NULL, OCI_DEFAULT);
   
      if (mQueryResult != OCI_SUCCESS && mQueryResult != OCI_SUCCESS_WITH_INFO && mQueryResult != OCI_NO_DATA) {
	 throw OracleException(mErrorHandle);
      }
   }
   
   catch (OracleException &theException)
   {
      L << Logger::Error << kModuleId << "Execute failed: " << theException.Reason() << endl;
      throw AhuException("Execute failed: " + theException.Reason());
   }

   if (mTimeQueries == true)
   {
      struct timeval theTime;
      
      gettimeofday(&theTime, NULL);

      double theDifference = theTime.tv_sec - theStartTime.tv_sec
         + (theTime.tv_usec - theStartTime.tv_usec) / 1000000.0;

      mTimeQueriesStream << theTime.tv_sec << "." << theTime.tv_sec << "\t" << theQueryType << "\t"
                         << theDifference << endl;
   }
}

bool OracleBackend::list(int domain_id)
{
   mQueryId = domain_id;

   if (mDebugQueries) {
      printf(">>> executing query: %s\n", mQueries[kListQuery]);
      printf(">>> :id = '%d'\n", mQueryId);
   }
   
   mActiveQuery = kListQuery;

   try
   {
      mQueryResult = OCIStmtExecute(mServiceContextHandle, mStatementHandles[kListQuery], mErrorHandle, 1, 0,
        (OCISnapshot *)NULL, (OCISnapshot*) NULL, OCI_DEFAULT);
   
      if (mQueryResult != OCI_SUCCESS && mQueryResult != OCI_SUCCESS_WITH_INFO && mQueryResult != OCI_NO_DATA) {
	 throw OracleException(mErrorHandle);
      }
   }

   catch (OracleException &theException)
   {
     L << Logger::Error << kModuleId << "Execute failed: " << theException.Reason() << endl;
     throw AhuException("Execute failed: " + theException.Reason());
   }

   return true;
}

bool OracleBackend::get(DNSResourceRecord &theRecord)
{
   if (mQueryResult == OCI_NO_DATA) 
      return false;
   
   theRecord.content       = mResultContent;
   theRecord.ttl           = mResultTTL;
   theRecord.priority      = mResultPriority;
   theRecord.qtype         = mResultType;
   theRecord.domain_id     = mResultDomainId;
   theRecord.last_modified = mResultChangeDate;

   // use this to distinguish between select with 'name' field (list()) and one without

   if (mActiveQuery != kListQuery) {
      theRecord.qname = mQueryName;
   } else {
      theRecord.qname = mResultName;
   }
   
   // Try to fetch the next one. We look at the result the next time we're being
   // called.
   
   try
   {
      mQueryResult = OCIStmtFetch(mStatementHandles[mActiveQuery], mErrorHandle, 1, 0, 0);
      if (mQueryResult != OCI_SUCCESS && mQueryResult != OCI_SUCCESS_WITH_INFO && mQueryResult != OCI_NO_DATA) {
	 new OracleException(mErrorHandle);  // ? - ahu
      }
    }
   catch (OracleException &theException)
   {
      L << Logger::Error << kModuleId << "Fetch failed: " << theException.Reason() << endl;
      throw AhuException("Execute failed: " + theException.Reason());
   }
   
   return true;
}

void OracleBackend::Cleanup()
{
   sword theError;

   L << Logger::Warning << kModuleId << "Cleaning up Oracle Backend" << endl;
   
   if (mTimeQueries == true) {
      mTimeQueriesStream.close();
   }
   
   for (int i = 0; i < kNumQueries; i++) {
      if (mStatementHandles[i] != NULL) {
         OCIHandleFree(mStatementHandles[i], OCI_HTYPE_STMT);
         mStatementHandles[i] = NULL;
      }
   }

   if (mServiceContextHandle != NULL) {
      theError = OCILogoff(mServiceContextHandle, mErrorHandle);
      if (theError != 0) {
         L << Logger::Warning << kModuleId << "OCILogoff returned a error (" << theError << ")" << endl;
      }
   }

/*
#if DITHOEFTNIETMEERNAEENOCILOGOFF
   if (mServiceContextHandle != NULL) {
      OCIHandleFree(mServiceContextHandle, OCI_HTYPE_SVCCTX);
      mServiceContextHandle = NULL;
   }
#endif
*/
   
   if (mErrorHandle != NULL) {
      OCIHandleFree(mErrorHandle, OCI_HTYPE_ERROR);
      mErrorHandle = NULL;
   }
   
   if (mEnvironmentHandle != NULL) {
      OCIHandleFree(mEnvironmentHandle, OCI_HTYPE_ENV);
      mEnvironmentHandle = NULL;
   }
}


class OracleFactory : public BackendFactory
{
   public:
      OracleFactory() : BackendFactory("oracle") {}

      void declareArguments(const string &suffix="")
      {
         declare(suffix,"debug-queries","Debugging output","no");
         declare(suffix,"time-queries","Output query timings to a file","no");
         declare(suffix,"uppercase","Uppercase database","no");
         declare(suffix,"database","Database to connect to","powerdns");
         declare(suffix,"username","Username to connect as","powerdns");
         declare(suffix,"password","Password to connect with","");
         declare(suffix,"home","Set and override ORACLE_HOME from within PDNS","");
         declare(suffix,"sid","Set and override ORACLE_SID from within PDNS","");

         declare(suffix, "forward-query", "", kDefaultQueries[0]);
         declare(suffix, "forward-query-by-zone", "", kDefaultQueries[1]);
         declare(suffix, "forward-any-query", "", kDefaultQueries[2]);
         declare(suffix, "forward-wildcard-query", "", kDefaultQueries[3]);
         declare(suffix, "forward-wildcard-any-query", "", kDefaultQueries[4]);
         declare(suffix, "list-query", "", kDefaultQueries[5]);
      }

      DNSBackend *make(const string &suffix="")
      {
	try {
	  return new OracleBackend(suffix);
	}
	catch(...) {}
	return 0;
      }
};


//! Magic class that is activated when the dynamic library is loaded
class OracleLoader
{
   public:
      
      //! This reports us to the main UeberBackend class
      
      OracleLoader()
      {
	BackendMakers().report(new OracleFactory);
	L << Logger::Warning << kModuleId << "Oracle Backend loaded." << endl;
      }
      
};
static OracleLoader loader;
