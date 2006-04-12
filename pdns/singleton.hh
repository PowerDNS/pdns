/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef SINGLETON_HH
#define SINGLETON_HH

#pragma warning ( disable: 4786 ) 

#define WINDOWS_LEAN_AND_MEAN
#include <windows.h>


//! A common singleton template class.
template <class _Ty>
class Singleton
{
private:
  static long m_refCount;   //! Reference counter.
  static _Ty *m_pInstance;  //! Pointer to the actual instance.
  
  //! No assign operator allowed.
  const _Ty & operator=( const _Ty & rhv )
  {
  }

  //! No copy constructor.
  Singleton( const _Ty & copy )
  {
  }
  
protected:
public:
  //! Default constructor.
  Singleton( void )
  {
    if ( m_refCount == 0 )
    {
      m_pInstance = reinterpret_cast< _Ty * >( this );
    }

    // Increase refcount.
    InterlockedIncrement( &m_refCount );
  }

  //! Destructor.
  virtual ~Singleton( void )
  {
    if ( m_refCount == 0 )
      return;

    if ( InterlockedDecrement( &m_refCount ) == 0 )
    {
      m_pInstance = NULL;
    }
  }

  //! Creates the singleton.
  static _Ty *create( void )
  {
    if ( m_refCount == 0 )
    {
      m_pInstance = new _Ty;
    }

    // Increase refcount.
    InterlockedIncrement( &m_refCount );

    return m_pInstance;
  }

  //! Releases the singleton.
  static void release( void )
  {
    if ( m_refCount == 0 )
      return;

    if ( InterlockedDecrement( &m_refCount ) == 0 )
    {
      // No more instances needed, delete object.
      delete m_pInstance;
      m_pInstance = NULL;
    }
  }

  //! Returns a pointer to the singleton.
  static _Ty *instance( void )
  {
    return m_pInstance;
  }

  //! Initializes the singleton.
  virtual bool init( void )
  {
    return true;
  }

  //! Shuts the singleton down.
  virtual bool shutdown( void )
  {
    return true;
  }
  
};


template <class _Ty>
_Ty *Singleton< _Ty >::m_pInstance = NULL;

template <class _Ty>
long Singleton< _Ty >::m_refCount = 0;


#endif // SINGLETON_HH
