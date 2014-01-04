/*
 *  Threading abstraction layer
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "polarssl/config.h"

#if defined(POLARSSL_THREADING_C)

#include "polarssl/threading.h"

#if defined(POLARSSL_THREADING_DUMMY)
static int threading_mutex_init_dummy( threading_mutex_t *mutex )
{
    ((void) mutex );
    return( 0 );
}

static int threading_mutex_free_dummy( threading_mutex_t *mutex )
{
    ((void) mutex );
    return( 0 );
}

static int threading_mutex_lock_dummy( threading_mutex_t *mutex )
{
    ((void) mutex );
    return( 0 );
}

static int threading_mutex_unlock_dummy( threading_mutex_t *mutex )
{
    ((void) mutex );
    return( 0 );
}

int (*polarssl_mutex_init)( threading_mutex_t * ) = threading_mutex_init_dummy;
int (*polarssl_mutex_free)( threading_mutex_t * ) = threading_mutex_free_dummy;
int (*polarssl_mutex_lock)( threading_mutex_t * ) = threading_mutex_lock_dummy;
int (*polarssl_mutex_unlock)( threading_mutex_t * ) = threading_mutex_unlock_dummy;
#endif /* POLARSSL_THREADING_DUMMY */

#if defined(POLARSSL_THREADING_PTHREAD)
static int threading_mutex_init_pthread( threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return( POLARSSL_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_init( mutex, NULL ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

static int threading_mutex_free_pthread( threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return( POLARSSL_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_destroy( mutex ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

static int threading_mutex_lock_pthread( threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return( POLARSSL_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_lock( mutex ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

static int threading_mutex_unlock_pthread( threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return( POLARSSL_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_unlock( mutex ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

int (*polarssl_mutex_init)( threading_mutex_t * ) = threading_mutex_init_pthread;
int (*polarssl_mutex_free)( threading_mutex_t * ) = threading_mutex_free_pthread;
int (*polarssl_mutex_lock)( threading_mutex_t * ) = threading_mutex_lock_pthread;
int (*polarssl_mutex_unlock)( threading_mutex_t * ) = threading_mutex_unlock_pthread;
#endif /* POLARSSL_THREADING_PTHREAD */

#if defined(POLARSSL_THREADING_ALT)
int (*polarssl_mutex_init)( threading_mutex_t * ) = NULL;
int (*polarssl_mutex_free)( threading_mutex_t * ) = NULL;
int (*polarssl_mutex_lock)( threading_mutex_t * ) = NULL;
int (*polarssl_mutex_unlock)( threading_mutex_t * ) = NULL;

int threading_set_alt( int (*mutex_init)( threading_mutex_t * ),
                       int (*mutex_free)( threading_mutex_t * ),
                       int (*mutex_lock)( threading_mutex_t * ),
                       int (*mutex_unlock)( threading_mutex_t * ) )
{
    polarssl_mutex_init = mutex_init;
    polarssl_mutex_free = mutex_free;
    polarssl_mutex_lock = mutex_lock;
    polarssl_mutex_unlock = mutex_unlock;

    return( 0 );
}
#endif /* POLARSSL_THREADING_ALT_C */

#endif /* POLARSSL_THREADING_C */
