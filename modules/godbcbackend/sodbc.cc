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
#include "pdns/logger.hh"
#include "pdns/utility.hh"
#include <sstream>
#include "sodbc.hh"
#include <string.h>

static bool realTestResult( SQLRETURN result, SQLSMALLINT type, SQLHANDLE handle, const std::string & message, std::string & errorMessage)
{
  // cerr<<"result = "<<result<<endl;
  if ( result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO )
    return true;

  ostringstream errmsg;

  errmsg << message << ": ";

  if ( result != SQL_ERROR && result != SQL_SUCCESS_WITH_INFO ) {
    cerr<<"handle "<<handle<<" got result "<<result<<endl;
    errmsg << "SQL function returned "<<result<<", no additional information available"<<endl;
    errorMessage = errmsg.str();
    return false;
  }

  SQLINTEGER i = 0;
  SQLINTEGER native;
  SQLCHAR state[ 7 ];
  SQLCHAR text[256];
  SQLSMALLINT len;
  SQLRETURN ret;

  do
  {
    // cerr<<"getting sql diag record "<<i<<endl;
    ret = SQLGetDiagRec(type, handle, ++i, state, &native, text,
    sizeof(text), &len );
    // cerr<<"getdiagrec said "<<ret<<endl;
    if (SQL_SUCCEEDED(ret)) { // cerr<<"got it"<<endl;
      errmsg<<state<<i<<native<<text<<"/";
    }
  }
  while( ret == SQL_SUCCESS );
  errorMessage = errmsg.str();
  return false;
}

class SODBCStatement: public SSqlStatement
{
public:
  SODBCStatement(const string& query, bool dolog, int nparams, SQLHDBC connection)
  {
    d_query = query;
    d_conn = connection;
    d_dolog = dolog;
    d_residx = 0;
    d_paridx = 0;
    d_result = SQL_NO_DATA;
    d_statement = NULL;
    d_prepared = false;
    m_columncount = 0;
    d_parnum = nparams;
  }

  struct ODBCParam {
    SQLPOINTER      ParameterValuePtr;
    SQLLEN*         LenPtr;
    SQLSMALLINT     ParameterType;
    SQLSMALLINT     ValueType;
  };

  vector<ODBCParam> d_req_bind;

  SSqlStatement* bind(const string& name, ODBCParam& p) {
    prepareStatement();
    d_req_bind.push_back(p);
    SQLRETURN result = SQLBindParameter(
      d_statement,           // StatementHandle,
      d_paridx+1,            // ParameterNumber,
      SQL_PARAM_INPUT,       // InputOutputType,
      p.ValueType,           // ValueType,
      p.ParameterType,       // ParameterType,
      0,                     // ColumnSize,
      0,                     // DecimalDigits,
      p.ParameterValuePtr,   // ParameterValuePtr,
      0,                     // BufferLength,
      p.LenPtr               // StrLen_or_IndPtr
    );
    testResult( result, SQL_HANDLE_STMT, d_statement, "Could not bind parameter.");
    d_paridx++;

    return this;
  }

  SSqlStatement* bind(const string& name, bool value) { prepareStatement(); return bind(name, (uint32_t)value); }

  SSqlStatement* bind(const string& name, long value) { prepareStatement(); return bind(name, (unsigned long)value); }

  SSqlStatement* bind(const string& name, int value) { prepareStatement(); return bind(name, (uint32_t)value); }

  SSqlStatement* bind(const string& name, long long value) { prepareStatement(); return bind(name, (unsigned long long)value); }

  SSqlStatement* bind(const string& name, uint32_t value) {
    prepareStatement();
    ODBCParam p;
    p.ParameterValuePtr = new UDWORD {value};
    p.LenPtr = new SQLLEN {sizeof(UDWORD)};
    p.ParameterType = SQL_INTEGER;
    p.ValueType = SQL_INTEGER;
    return bind(name, p);
  }

  SSqlStatement* bind(const string& name, unsigned long value) {
    prepareStatement();
    ODBCParam p;
    p.ParameterValuePtr = new ULONG {value};
    p.LenPtr = new SQLLEN {sizeof(ULONG)};
    p.ParameterType = SQL_INTEGER;
    p.ValueType = SQL_INTEGER;
    return bind(name, p);
  }

  SSqlStatement* bind(const string& name, unsigned long long value) {
    prepareStatement();
    ODBCParam p;
    p.ParameterValuePtr = new unsigned long long {value};
    p.LenPtr = new SQLLEN {sizeof(unsigned long long)};
    p.ParameterType = SQL_BIGINT;
    p.ValueType = SQL_C_UBIGINT;
    return bind(name, p);
  }

  SSqlStatement* bind(const string& name, const std::string& value) {

    // cerr<<"asked to bind string "<<value<<endl;

    if(d_req_bind.size() > (d_parnum+1)) throw SSqlException("Trying to bind too many parameters.");
    prepareStatement();
    ODBCParam p;

    p.ParameterValuePtr = (char*) new char[value.size()+1];
    value.copy((char*)p.ParameterValuePtr, value.size());
    ((char*)p.ParameterValuePtr)[value.size()]=0;
    p.LenPtr=new SQLLEN;
    *(p.LenPtr)=value.size();
    p.ParameterType = SQL_VARCHAR;
    p.ValueType = SQL_C_CHAR;

    return bind(name, p);
  }

  SSqlStatement* bindNull(const string& name) {
    if(d_req_bind.size() > (d_parnum+1)) throw SSqlException("Trying to bind too many parameters.");

    prepareStatement();
    ODBCParam p;

    p.ParameterValuePtr = NULL;
    p.LenPtr=new SQLLEN;
    *(p.LenPtr)=SQL_NULL_DATA;
    p.ParameterType = SQL_VARCHAR;
    p.ValueType = SQL_C_CHAR;

    return bind(name, p);
  }

  SSqlStatement* execute()
  {
    prepareStatement();
    SQLRETURN result;
    // cerr<<"execute("<<d_query<<")"<<endl;
    if (d_dolog) {
      g_log<<Logger::Warning<<"Query: "<<d_query<<endl;
    }

    result = SQLExecute(d_statement);
    if(result != SQL_NO_DATA)  // odbc+sqlite returns this on 'no rows updated'
        testResult( result, SQL_HANDLE_STMT, d_statement, "Could not execute query ("+d_query+")." );

    // Determine the number of columns.
    result = SQLNumResultCols( d_statement, &m_columncount );
    testResult( result, SQL_HANDLE_STMT, d_statement, "Could not determine the number of columns." );
    // cerr<<"got "<<m_columncount<<" columns"<<endl;

    if(m_columncount) {
      // cerr<<"first SQLFetch"<<endl;
      d_result = SQLFetch(d_statement);
      // cerr<<"first SQLFetch done, d_result="<<d_result<<endl;
    }
    else
      d_result = SQL_NO_DATA;

    if(d_result != SQL_NO_DATA)
        testResult( d_result, SQL_HANDLE_STMT, d_statement, "Could not do first SQLFetch for ("+d_query+")." );
    return this;
  }

  bool hasNextRow() {
    // cerr<<"hasNextRow d_result="<<d_result<<endl;
    return d_result!=SQL_NO_DATA;
  }
  SSqlStatement* nextRow(row_t& row);

  SSqlStatement* getResult(result_t& result) {
    result.clear();
    // if (d_res == NULL) return this;
    row_t row;
    while(hasNextRow()) { nextRow(row); result.push_back(row); }
    return this;
  }

  SSqlStatement* reset() {
    SQLCloseCursor(d_statement); // hack, this probably violates some state transitions

    for(auto &i: d_req_bind) {
      if (i.ParameterType == SQL_VARCHAR) delete [] (char*)i.ParameterValuePtr;
      else if (i.ParameterType == SQL_INTEGER) delete (ULONG*)i.ParameterValuePtr;
      else if (i.ParameterType == SQL_C_UBIGINT) delete (unsigned long long*)i.ParameterValuePtr;
      delete i.LenPtr;
    }
    d_req_bind.clear();
    d_residx = 0;
    d_paridx = 0;
    return this;
  }
  const std::string& getQuery() { return d_query; }

  ~SODBCStatement() {
    releaseStatement();
  }
private:

  void testResult(SQLRETURN result, SQLSMALLINT type, SQLHANDLE handle, const std::string & message) {
     std::string errorMessage;
     if (!realTestResult(result, type, handle, message, errorMessage)) {
       releaseStatement();
       throw SSqlException(errorMessage);
     }
  }

  void releaseStatement() {
    reset();
    if (d_statement != NULL)
      SQLFreeHandle(SQL_HANDLE_STMT, d_statement);
    d_prepared = false;
  }

  void prepareStatement() {
    if (d_prepared) return;

    SQLRETURN result;

    // Allocate statement handle.
    result = SQLAllocHandle( SQL_HANDLE_STMT, d_conn, &d_statement );
    testResult( result, SQL_HANDLE_DBC, d_conn, "Could not allocate a statement handle." );

    result = SQLPrepare(d_statement, (SQLCHAR *) d_query.c_str(), SQL_NTS);
    testResult( result, SQL_HANDLE_STMT, d_statement, "Could not prepare query." );

    SQLSMALLINT paramcount;
    result = SQLNumParams(d_statement, &paramcount);
    testResult( result, SQL_HANDLE_STMT, d_statement, "Could not get parameter count." );

    if (paramcount != static_cast<SQLSMALLINT>(d_parnum)) {
      releaseStatement();
      throw SSqlException("Provided parameter count does not match statement: " + d_query);
    }

    // cerr<<"prepared ("<<query<<")"<<endl;
    d_prepared = true;
  }

  string d_query;
  bool d_dolog;
  bool d_prepared;
  int d_residx;
  size_t d_paridx,d_parnum;
  SQLRETURN d_result;

  SQLHDBC d_conn;
  SQLHSTMT d_statement;    //!< Database statement handle.

  //! Column type.
  struct column_t
  {
    SQLSMALLINT m_type;       //!< Type of the column.
    SQLULEN     m_size;       //!< Column size.
    SQLPOINTER  m_pData;      //!< Pointer to the memory where to store the data.
    bool        m_canBeNull;  //!< Can this column be null?
  };

  //! Column info.
  SQLSMALLINT m_columncount;

};

SSqlStatement* SODBCStatement::nextRow(row_t& row)
{
  SQLRETURN result;

  row.clear();

  result = d_result;
  // cerr<<"at start of nextRow, previous SQLFetch result is "<<result<<endl;
  // FIXME handle errors (SQL_NO_DATA==100, anything other than the two SUCCESS options below is bad news)
  if ( result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO )
  {
    // cerr<<"got row"<<endl;
    // We've got a data row, now lets get the results.
    for ( int i = 0; i < m_columncount; i++ )
    {
      SQLLEN len;
      SQLCHAR coldata[128*1024];
      std::string strres = "";
      result = SQLGetData( d_statement, i + 1, SQL_C_CHAR, (SQLPOINTER) coldata, sizeof(coldata), &len);
      testResult( result, SQL_HANDLE_STMT, d_statement, "Could not get data." );
      if (len > SQL_NULL_DATA)
        strres = std::string(reinterpret_cast<const char*>(coldata), std::min<SQLLEN>(sizeof(coldata)-1,len)); // do not use nil byte
      row.push_back(strres);
    }

    // Done!
    d_residx++;
    // cerr<<"SQLFetch"<<endl;
    d_result = SQLFetch(d_statement);
    // cerr<<"subsequent SQLFetch done, d_result="<<d_result<<endl;
    if(d_result == SQL_NO_DATA) {
      SQLRETURN result2 = SQLMoreResults(d_statement);
      // cerr<<"SQLMoreResults done, result="<<d_result2<<endl;
      if (result2 == SQL_NO_DATA) {
        d_result = result2;
      }
      else {
        testResult( result2, SQL_HANDLE_STMT, d_statement, "Could not fetch next result set for ("+d_query+").");
      d_result = SQLFetch(d_statement);
      }
    }
    testResult( result, SQL_HANDLE_STMT, d_statement, "Could not do subsequent SQLFetch for ("+d_query+")." );

    return this;
  }

  SQLFreeStmt( d_statement, SQL_CLOSE );
  throw SSqlException( "Should not get here." );
  return this;
}

// Constructor.
SODBC::SODBC(
             const std::string & dsn,
             const std::string & username,
             const std::string & password
            )
{
  SQLRETURN     result;

  // Allocate an environment handle.
  result = SQLAllocHandle( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_environment );
  testResult( result, SQL_NULL_HANDLE, NULL, "Could not allocate an environment handle." );

  // Set ODBC version. (IEUW!)
  result = SQLSetEnvAttr( m_environment, SQL_ATTR_ODBC_VERSION, reinterpret_cast< void * >( SQL_OV_ODBC3 ), 0 );
  testResult( result, SQL_HANDLE_ENV, m_environment, "Could not set the ODBC version." );

  // Allocate connection handle.
  result = SQLAllocHandle( SQL_HANDLE_DBC, m_environment, &m_connection );
  testResult( result, SQL_HANDLE_ENV, m_environment, "Could not allocate a connection handle." );

  // Connect to the database.
  char *l_dsn       = strdup( dsn.c_str());
  char *l_username  = strdup( username.c_str());
  char *l_password  = strdup( password.c_str());

  result = SQLConnect( m_connection,
    reinterpret_cast< SQLTCHAR * >( l_dsn ), dsn.length(),
    reinterpret_cast< SQLTCHAR * >( l_username ), username.length(),
    reinterpret_cast< SQLTCHAR * >( l_password ), password.length());

  free( l_dsn );
  free( l_username );
  free( l_password );

  testResult( result, SQL_HANDLE_DBC, m_connection, "Could not connect to ODBC datasource." );


  m_busy  = false;
  m_log   = false;
}


// Destructor.
SODBC::~SODBC( void )
{
  // Disconnect from database and free all used resources.
  // SQLFreeHandle( SQL_HANDLE_STMT, m_statement );

  SQLDisconnect( m_connection );

  SQLFreeHandle( SQL_HANDLE_DBC, m_connection );
  SQLFreeHandle( SQL_HANDLE_ENV, m_environment );

  // Free all allocated column memory.
  // for ( int i = 0; i < m_columnInfo.size(); i++ )
  // {
  //   if ( m_columnInfo[ i ].m_pData )
  //     delete m_columnInfo[ i ].m_pData;
  // }
}

// Executes a command.
void SODBC::execute( const std::string & command )
{
  SODBCStatement stmt(command, m_log, 0, m_connection);

  stmt.execute()->reset();
}

// Sets the log state.
void SODBC::setLog( bool state )
{
  m_log = state;
}

// Returns an exception.
SSqlException SODBC::sPerrorException( const std::string & reason )
{
  return SSqlException( reason );
}

std::unique_ptr<SSqlStatement> SODBC::prepare(const string& query, int nparams)
{
  return std::unique_ptr<SSqlStatement>(new SODBCStatement(query, m_log, nparams, m_connection));
}


void SODBC::startTransaction() {
  // cerr<<"starting transaction"<<endl;
  SQLRETURN result;
  result = SQLSetConnectAttr(m_connection, SQL_ATTR_AUTOCOMMIT, SQL_AUTOCOMMIT_OFF, 0);
  testResult( result, SQL_HANDLE_DBC, m_connection, "startTransaction (enable autocommit) failed" );
}

void SODBC::commit() {
  // cerr<<"commit!"<<endl;
  SQLRETURN result;

  result = SQLEndTran(SQL_HANDLE_DBC, m_connection, SQL_COMMIT); // don't really need this, AUTOCOMMIT_OFF below will also commit
  testResult( result, SQL_HANDLE_DBC, m_connection, "commit failed" );

  result = SQLSetConnectAttr(m_connection, SQL_ATTR_AUTOCOMMIT, SQL_AUTOCOMMIT_OFF, 0);
  testResult( result, SQL_HANDLE_DBC, m_connection, "disabling autocommit after commit failed" );
}

void SODBC::rollback() {
  // cerr<<"rollback!"<<endl;
  SQLRETURN result;

  result = SQLEndTran(SQL_HANDLE_DBC, m_connection, SQL_ROLLBACK);
  testResult( result, SQL_HANDLE_DBC, m_connection, "rollback failed" );

  result = SQLSetConnectAttr(m_connection, SQL_ATTR_AUTOCOMMIT, SQL_AUTOCOMMIT_OFF, 0);
  testResult( result, SQL_HANDLE_DBC, m_connection, "disabling autocommit after rollback failed" );
}

void SODBC::testResult(SQLRETURN result, SQLSMALLINT type, SQLHANDLE handle, const std::string & message) {
  std::string errorMessage;
  if (!realTestResult(result, type, handle, message, errorMessage)) throw SSqlException(errorMessage);
}
