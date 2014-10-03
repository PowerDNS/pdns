// $Id$

#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>

#include "pdns/namespaces.hh"

#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/pdnsexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>

#include "DB2Exception.hh"
#include "DB2Backend.hh"

static const string kBackendName="[DB2Backend]";

static const int kForwardQuery            = 0;
static const int kForwardByZoneQuery      = 1;
static const int kForwardAnyQuery         = 2;
static const int kForwardWildcardQuery    = 3;
static const int kForwardWildcardAnyQuery = 4;

static const int kListQuery               = 5;
      
static const int kNumQueries              = 6;

static const char *kQueries[kNumQueries] =
{
   // ForwardQuery
   "select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where Name = ? and type = ?",
   
   // ForwardByZoneQuery
   "select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where Name = ? and Type = ? and ZoneId = ?",
         
   // ForwardAnyQuery
   "select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where Name = ?",
   
   // ForwardWildcardQuery
   "select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where Name like ? and Type = ?",
   
   // ForwardWildcardAnyQuery
   "select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where Name like ?",
   
   // ListQuery
   "select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where ZoneId = ?"
};

static const char *kSoaQuery = "select Id,Hostmaster,Serial from Zones where Active = 1 and Name = ?";

DB2Backend::DB2Backend(const string &suffix)
{
   SQLRETURN theError;

   // Initialize the handles
   mConnection = SQL_NULL_HANDLE;
   mEnvironment = SQL_NULL_HANDLE;
   for (int i = 0; i < kNumQueries; i++) {
      mStatements[i] = SQL_NULL_HANDLE;
   }

   try
   {
      // Allocate the Environment Handle
      theError = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &mEnvironment);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError);
      }

      // Allocate a Connection Handle
      theError = SQLAllocHandle(SQL_HANDLE_DBC, mEnvironment, &mConnection);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_ENV, mEnvironment);
      }

      // Try to connect to the database
      theError = SQLConnect(mConnection, (SQLCHAR*) arg()["db2-"+suffix+"server"].c_str(), SQL_NTS, (SQLCHAR*) arg()["db2-"+suffix+"user"].c_str(), SQL_NTS, (SQLCHAR*) arg()["db2-"+suffix+"password"].c_str(), SQL_NTS);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_DBC, mConnection);
      }

      // Set autocommit to off
      theError = SQLSetConnectAttr(mConnection, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER) SQL_AUTOCOMMIT_OFF, SQL_NTS);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_DBC, mConnection);
      }

      // Prepare the statements
      for (int i = 0; i < kNumQueries; i++)
      {
         // Allocate a Statement Handle
         theError = SQLAllocHandle(SQL_HANDLE_STMT, mConnection, &(mStatements[i]));
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mConnection);
         }         

         // Prepare the statement
         theError = SQLPrepare(mStatements[i], (SQLCHAR*) kQueries[i], SQL_NTS);
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
         }

         //
         // Bind Parameters
         //

         // Bind the Name parameter to all queries except the list statements
         if (i != kListQuery) {
            theError = SQLBindParameter(mStatements[i], 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 256, 0, mParamName, 256, NULL);
            if (theError != SQL_SUCCESS) {
               throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
            }
         }

         // Bind the Type parameter only to the kForwardQuery, kForwardByZoneQuery and kForwardWildcardQuery statements
         if (i == kForwardQuery || i == kForwardByZoneQuery || i == kForwardWildcardQuery) {
            theError = SQLBindParameter(mStatements[i], 2, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 256, 0, mParamType, 256, NULL);
            if (theError != SQL_SUCCESS) {
               throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
            }
         }

         // Bind the ZoneId parameter for the kForwardByZoneQuery and kListQuery queries
         if (i == kForwardByZoneQuery || i == kListQuery) {
            int theIndex = (i == kForwardByZoneQuery) ? 3 : 1;            
            theError = SQLBindParameter(mStatements[i], theIndex, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER, 0, 0, &mParamZoneId, 0, NULL);
            if (theError != SQL_SUCCESS) {
               throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
            }            
         }

         //
         // Bind Columns
         //

         // Bind the Content column
         mResultContentIndicator = 0;
         theError = SQLBindCol(mStatements[i], 1, SQL_C_CHAR, mResultContent, sizeof(mResultContent), &mResultContentIndicator);
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
         }

         // Bind the TimeToLive column
         mResultTimeToLiveIndicator = 0;
         theError = SQLBindCol(mStatements[i], 2, SQL_C_LONG, &mResultTimeToLive, sizeof(mResultTimeToLive), &mResultTimeToLiveIndicator);
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
         }

         // Bind the Priority column
         mResultPriorityIndicator = 0;
         theError = SQLBindCol(mStatements[i], 3, SQL_C_LONG, &mResultPriority, sizeof(mResultZoneId), &mResultPriorityIndicator);
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
         }

         // Bind the Type column
         mResultTypeIndicator = 0;
         theError = SQLBindCol(mStatements[i], 4, SQL_C_CHAR, mResultType, sizeof(mResultType), &mResultTypeIndicator);
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
         }

         // Bind the ZoneId column
         mResultZoneIdIndicator = 0;
         theError = SQLBindCol(mStatements[i], 5, SQL_C_LONG, &mResultZoneId, sizeof(mResultZoneId), &mResultZoneIdIndicator);
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
         }

         // Bind the ChangeDate column
         mResultChangeDateIndicator = 0;
         theError = SQLBindCol(mStatements[i], 6, SQL_C_LONG, &mResultChangeDate, sizeof(mResultChangeDate), &mResultChangeDateIndicator);
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
         }
         
         // Bind the Name column
         mResultNameIndicator = 0;
         theError = SQLBindCol(mStatements[i], 7, SQL_C_CHAR, mResultName, sizeof(mResultName), &mResultNameIndicator);
         if (theError != SQL_SUCCESS) {
            throw DB2Exception(theError, SQL_HANDLE_DBC, mStatements[i]);
         }

         mStatementStates[i] = false;
      }

      //
      // Construct the SOA Query
      //

      // Prepare the SOA Query
      theError = SQLAllocHandle(SQL_HANDLE_STMT, mConnection, &mSoaStatement);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_DBC, mConnection);
      }

      theError = SQLPrepare(mSoaStatement, (SQLCHAR*) kSoaQuery, SQL_NTS);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mSoaStatement);
      }

      // Bind the Name parameter      
      theError = SQLBindParameter(mSoaStatement, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR, 256, 0, mSoaParamName, 256, NULL);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mSoaStatement);
      }

      // Bind the ZoneId column
      mSoaResultZoneIdIndicator = 0;
      theError = SQLBindCol(mSoaStatement, 1, SQL_C_LONG, &mSoaResultZoneId, sizeof(mSoaResultZoneId), &mSoaResultZoneIdIndicator);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mSoaStatement);
      }      

      // Bind the Hostmaster column
      mSoaResultHostmasterIndicator = 0;
      theError = SQLBindCol(mSoaStatement, 2, SQL_C_CHAR, mSoaResultHostmaster, 256, &mSoaResultHostmasterIndicator);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mSoaStatement);
      }

      // Bind the Serial column
      mSoaResultSerialIndicator = 0;
      theError = SQLBindCol(mSoaStatement, 3, SQL_C_LONG, &mSoaResultSerial, sizeof(mSoaResultSerial), &mSoaResultSerialIndicator);
      if (theError != SQL_SUCCESS) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mSoaStatement);
      }
   }
   
   catch (DB2Exception& theException)
   {
      //
      // Print out diagnostics
      //
      
      int theNativeError;
      string theSqlState, theSqlMessage;
      
      while (theException.GetNextSqlError(theNativeError, theSqlState, theSqlMessage) == true) {
         L << Logger::Warning << kBackendName << " Statement initialization failed with error " << theNativeError << endl;
         L << Logger::Warning << kBackendName << "  SQL State : " << theSqlState << endl;
         L << Logger::Warning << kBackendName << "  SQL Msg   : " << theSqlMessage << endl;
      }
      
      this->Cleanup();
      throw PDNSException("DB2Backend Failed to Start");
   }
   
   L << Logger::Warning << kBackendName << " Connection succeeded" << endl;
}

void DB2Backend::Cleanup()
{
   for (int i = 0; i < kNumQueries; i++) {
      if (mStatements[i] != SQL_NULL_HANDLE) {
         (void) SQLFreeHandle(SQL_HANDLE_STMT, mStatements[i]);
      }
   }

   if (mConnection != SQL_NULL_HANDLE) {
      (void) SQLFreeHandle(SQL_HANDLE_DBC, mConnection);
   }
   
   if (mEnvironment != SQL_NULL_HANDLE) {
      (void) SQLFreeHandle(SQL_HANDLE_ENV, mEnvironment);
   }
}

DB2Backend::~DB2Backend()
{
   this->Cleanup();
}

void DB2Backend::lookup(const QType &qtype, const string &qname, DNSPacket *pkt_p, int zoneId )
{
   SQLRETURN theError;

   //
   // Choose the right query. All this logic and the query types could be
   // moved to the API. Saves duplicate code in backends.
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
            theQueryType = kForwardByZoneQuery;
         } else {
            theQueryType = kForwardQuery;
         }
      }
   }
   
   //
   // Fill in the correct query parameters
   //

   //cerr << ">>>>>>>> Query = " << kQueries[theQueryType] << endl;
   
   switch (theQueryType)
   {
      case kForwardQuery:
      case kForwardWildcardQuery:
         strncpy(mParamName, qname.c_str(), sizeof(mParamName));
         strncpy(mParamType, qtype.getName().c_str(), sizeof(mParamType));
         //cerr << ">>>>>>>>  Name = " << mParamName << " Type = " << mParamType << endl;
         break;

      case kForwardByZoneQuery:
         strncpy(mParamName, qname.c_str(), sizeof(mParamName));
         strncpy(mParamType, qtype.getName().c_str(), sizeof(mParamType));	 
         mParamZoneId = zoneId;
         //cerr << ">>>>>>>>  Name = " << mParamName << " Type = " << mParamType << " ZoneId = " << mParamZoneId << endl;
         break;

      case kForwardAnyQuery:
      case kForwardWildcardAnyQuery:
         strncpy(mParamName, qname.c_str(), sizeof(mParamName));
         //cerr << ">>>>>>>>  Name = " << mParamName << endl;
         break;
   }

   //
   // Execute the query
   //

   try
   {
      //
      // Close the cursor if it is in use
      //

      if (mStatementStates[theQueryType] == true) {
         theError = SQLCloseCursor(mStatements[theQueryType]);
         if (theError != SQL_SUCCESS && theError != SQL_SUCCESS_WITH_INFO) {
            throw DB2Exception(theError, SQL_HANDLE_STMT, mStatements[theQueryType]);
         }
      }

      //
      // Execute the query
      //

      mResultContent[0] = mResultType[0] = mResultName[0] = 0x00;
      mResultTimeToLive = mResultPriority = mResultZoneId = mResultChangeDate = 0;
      
      theError = SQLExecute(mStatements[theQueryType]);
      if (theError != SQL_SUCCESS && theError != SQL_SUCCESS_WITH_INFO && theError != SQL_NO_DATA_FOUND) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mStatements[theQueryType]);
      }

      mCurrentStatement = mStatements[theQueryType];
      mStatementStates[theQueryType] = true;
   }
   
   catch (DB2Exception& theException)
   {
      //
      // Print out diagnostics
      //
      
      int theNativeError;
      string theSqlState, theSqlMessage;
      
      while (theException.GetNextSqlError(theNativeError, theSqlState, theSqlMessage) == true) {
         L << Logger::Warning << kBackendName << " SQLExecute() failed with error " << theNativeError << endl;
         L << Logger::Warning << kBackendName << "  SQL State : " << theSqlState << endl;
         L << Logger::Warning << kBackendName << "  SQL Msg   : " << theSqlMessage << endl;
      }

      //
      // Rethrow for the nameserver
      //
      
      throw PDNSException("Execute failed");
   }
}

bool DB2Backend::list(int inZoneId)
{
   SQLRETURN theError;
   bool theResult = false;

   try
   {
      //
      // Close the cursor
      //
      
      if (mStatementStates[kListQuery] == true) {
         theError = SQLCloseCursor(mStatements[kListQuery]);
         if (theError != SQL_SUCCESS && theError != SQL_SUCCESS_WITH_INFO) {
            throw DB2Exception(theError, SQL_HANDLE_STMT, mCurrentStatement);
         }
      }

      //
      // Execute the query
      //

      mParamZoneId = inZoneId;

      theError = SQLExecute(mStatements[kListQuery]);
      if (theError != SQL_SUCCESS && theError != SQL_SUCCESS_WITH_INFO && theError != SQL_NO_DATA_FOUND) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mStatements[kListQuery]);
      }

      mCurrentStatement = mStatements[kListQuery];
      mStatementStates[kListQuery] = true;

      if (theResult != SQL_NO_DATA_FOUND) {
         theResult = true;
      }
   }

   catch (DB2Exception& theException)
   {
      throw PDNSException("List failed");
   }

   return theResult;
}

bool DB2Backend::get(DNSResourceRecord& outRecord)
{
   bool theResult = false;

   try
   {
      //
      // Fetch a record
      //

      SQLRETURN theError = SQLFetch(mCurrentStatement);
      if (theError != SQL_SUCCESS && theError != SQL_SUCCESS_WITH_INFO && theError != SQL_NO_DATA_FOUND) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mCurrentStatement);
      }

      //
      // If we have data then return it
      //
   
      //cerr << ">>>>>>>> Get theError = " << theError << endl;

      if (theError != SQL_NO_DATA_FOUND)
      {
         //cerr << ">>>>>>>> Name    = " << mResultName << endl;
         //cerr << ">>>>>>>> Content = " << mResultContent << endl;
         //cerr << ">>>>>>>> Type    = " << mResultType << endl;
         
         outRecord.content       = mResultContent;
         outRecord.ttl           = mResultTimeToLive;
         outRecord.priority      = mResultPriority;
         outRecord.qtype         = mResultType;
         outRecord.domain_id     = mResultZoneId;
         outRecord.last_modified = mResultChangeDate;
         outRecord.qname         = mResultName;
         
         theResult = true;
      }
   }

   catch (DB2Exception& theException)
   {
      //
      // Print out diagnostics
      //
      
      int theNativeError;
      string theSqlState, theSqlMessage;
      
      while (theException.GetNextSqlError(theNativeError, theSqlState, theSqlMessage) == true) {
         L << Logger::Warning << kBackendName << " SQLFetch() failed with error " << theNativeError << endl;
         L << Logger::Warning << kBackendName << "  SQL State : " << theSqlState << endl;
         L << Logger::Warning << kBackendName << "  SQL Msg   : " << theSqlMessage << endl;
      }

      //
      // Rethrow for the nameserver
      //
      
      throw PDNSException("Fetch failed");
   }
   
   return theResult;
}

bool DB2Backend::getSOA(const string& inZoneName, SOAData& outSoaData)
{
   bool theResult = false;
   
   try
   {
      //
      // Execute the query
      //

      strncpy(mSoaParamName, inZoneName.c_str(), sizeof(mSoaParamName));

      SQLRETURN theError = SQLExecute(mSoaStatement);
      if (theError != SQL_SUCCESS && theError != SQL_SUCCESS_WITH_INFO && theError != SQL_NO_DATA_FOUND) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mSoaStatement);
      }      

      if (theError != SQL_NO_DATA_FOUND)
      {
         mSoaResultZoneId = mSoaResultSerial = 0;
         mSoaResultHostmaster[0] = mSoaResultNameserver[0] = 0x00;

         theError = SQLFetch(mSoaStatement);
         if (theError != SQL_SUCCESS && theError != SQL_SUCCESS_WITH_INFO) {
            throw DB2Exception(theError, SQL_HANDLE_STMT, mSoaStatement);
         }
         
         outSoaData.domain_id   = mSoaResultZoneId;         
         outSoaData.nameserver  = arg()["default-soa-name"];
         outSoaData.hostmaster  = mSoaResultHostmaster;
         outSoaData.serial      = mSoaResultSerial;         
         outSoaData.refresh     = 10800;
         outSoaData.retry       = 3600;
         outSoaData.expire      = 604800;
         outSoaData.default_ttl = 3600;
         
         theResult = true;
      }
      
      //
      // Close the cursor
      //

      theError = SQLCloseCursor(mSoaStatement);
      if (theError != SQL_SUCCESS && theError != SQL_SUCCESS_WITH_INFO) {
         throw DB2Exception(theError, SQL_HANDLE_STMT, mSoaStatement);
      }
   }

   catch (DB2Exception& theException)
   {
      //
      // Print out diagnostics
      //
      
      int theNativeError;
      string theSqlState, theSqlMessage;
      
      while (theException.GetNextSqlError(theNativeError, theSqlState, theSqlMessage) == true) {
         L << Logger::Warning << kBackendName << " SOA Record Lookup Failed: " << theNativeError << endl;
         L << Logger::Warning << kBackendName << "  SQL State : " << theSqlState << endl;
         L << Logger::Warning << kBackendName << "  SQL Msg   : " << theSqlMessage << endl;
      }

      //
      // Rethrow for the nameserver
      //
      
      throw PDNSException("GetSOA failed");
   }
   
   return theResult;
}

//! For the dynamic loader
DNSBackend *DB2Backend::maker()
{
   DNSBackend *theBackend;
   
   try {
      theBackend = new DB2Backend;
   } catch (...) {
      theBackend = NULL;
   }
   
   return theBackend;
}

class DB2Factory : public BackendFactory
{
   public:

      DB2Factory() : BackendFactory("db2") {}
  
      void declareArguments(const string &suffix="")
      {
         declare(suffix,"server","Server","powerdns");
         declare(suffix,"user","User","powerdns");
         declare(suffix,"password","Password","powerdns");
      }
      
      DNSBackend *make(const string &suffix="")
      {
         return new DB2Backend(suffix);
      }
};


//! Magic class that is activated when the dynamic library is loaded
class DB2Loader
{
   public:

      Loader()
      {
         BackendMakers().report(new DB2Factory);
         L << Logger::Info << "[db2backend] This is the db2 backend version " VERSION " reporting" << endl;
      }
};

static DB2Loader db2loader;
