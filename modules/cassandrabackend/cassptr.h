#pragma once

#include <cassandra.h>

template<class T, void (*Deleter)(T*)>
class CassPtr
{
public:
    CassPtr()
        : m_ptr(nullptr)
    {
    }

    CassPtr(T* ptr)
        : m_ptr(ptr)
    {
    }

    ~CassPtr()
    {
        reset();
    }

    CassPtr(const CassPtr&) = delete;
    CassPtr& operator=(const CassPtr&) = delete;

    CassPtr(CassPtr&& other)
        : m_ptr(other.m_ptr)
    {
        other.m_ptr = nullptr;
    }

    CassPtr& operator=(CassPtr&& other)
    {
        std::swap(m_ptr, other.m_ptr);
        return *this;
    }

    operator T*()
    {
        return m_ptr;
    }

    explicit operator bool() const
    {
        return m_ptr != nullptr;
    }

    void operator=(T* other)
    {
        reset(other);
    }

    void reset(T* other = nullptr)
    {
        if (m_ptr)
        {
            Deleter(m_ptr);
        }

        m_ptr = other;
    }

private:
    T*      m_ptr;
};

using CassIteratorPtr   = CassPtr<CassIterator,     &cass_iterator_free>;
using CassResultPtr     = CassPtr<const CassResult, &cass_result_free>;
using CassStatementPtr  = CassPtr<CassStatement,    &cass_statement_free>;
using CassFuturePtr     = CassPtr<CassFuture,       &cass_future_free>;
using CassSessionPtr    = CassPtr<CassSession,      &cass_session_free>;
using CassClusterPtr    = CassPtr<CassCluster,      &cass_cluster_free>;
