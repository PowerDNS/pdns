// $Id$

#include "DB2Exception.hh"

DB2Exception::DB2Exception(SQLRETURN inError)
   : mError(inError), mHandle(SQL_NULL_HANDLE), mErrorIndex(1)
{
}

DB2Exception::DB2Exception(SQLRETURN inError, SQLSMALLINT inHandleType, SQLHANDLE inHandle)
   : mError(inError), mHandle(inHandle), mHandleType(inHandleType), mErrorIndex(1)
{
}

SQLRETURN DB2Exception::GetError()
{
   return mError;
}

bool DB2Exception::GetNextSqlError(int& outNativeError, string& outSqlState, string& outSqlMessage)
{
   SQLCHAR     message[SQL_MAX_MESSAGE_LENGTH + 1];
   SQLCHAR     sqlstate[SQL_SQLSTATE_SIZE + 1];
   SQLINTEGER  sqlcode;
   SQLSMALLINT length;

   bool theResult = false;

   if (mHandle != SQL_NULL_HANDLE)
   {
      SQLRETURN theError = SQLGetDiagRec(mHandleType, mHandle, mErrorIndex, sqlstate, &sqlcode, message, SQL_MAX_MESSAGE_LENGTH + 1, &length);
      if (theError == SQL_SUCCESS)
      {
         outNativeError = sqlcode;
         outSqlState = (const char*) sqlstate;
         outSqlMessage = (const char*) message;

         mErrorIndex++;
         theResult = true;
      }
   }

   return theResult;
}
