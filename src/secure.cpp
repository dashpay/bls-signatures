// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.MIT or https://opensource.org/license/MIT

#include "secure.h"
#include "util.hpp"

#include <new>
#include <stdexcept>
#include <utility>

namespace bls {
namespace util {
namespace {
Util::SecureAllocCallback g_pfnSecureAlloc{nullptr};
Util::SecureFreeCallback g_pfnSecureFree{nullptr};
} // anonymous namespace

void SetSecureAllocator(Util::SecureAllocCallback pfnAlloc,
                        Util::SecureFreeCallback pfnFree)
{
    if (pfnAlloc == nullptr || pfnFree == nullptr) {
        throw std::invalid_argument("secure allocator must not be null");
    }
    g_pfnSecureAlloc = pfnAlloc;
    g_pfnSecureFree = pfnFree;
}

void GetSecureAllocator(Util::SecureAllocCallback* ppfnAlloc,
                        Util::SecureFreeCallback* ppfnFree)
{
    if (ppfnAlloc != nullptr) {
        *ppfnAlloc = g_pfnSecureAlloc;
    }
    if (ppfnFree != nullptr) {
        *ppfnFree = g_pfnSecureFree;
    }
}

void* SecMalloc(size_t nBytes)
{
    if (g_pfnSecureAlloc == nullptr) {
        throw std::runtime_error("secure allocator used before BLS::Init");
    }
    void* pAllocation = g_pfnSecureAlloc(nBytes);
    if (pAllocation == nullptr) {
        throw std::bad_alloc();
    }
    return pAllocation;
}

void SecFree(void* ptr, size_t nBytes)
{
    SecureWipe(ptr, nBytes);
    if (g_pfnSecureFree == nullptr) {
        return;
    }
    g_pfnSecureFree(ptr);
}

Bn::Bn()
{
    bn_null(m_val);
    bn_new(m_val);
    bn_zero(m_val);
}

Bn::~Bn()
{
    SecureWipe(m_val, sizeof(bn_st));
    bn_free(m_val);
}

Bn::Bn(Bn&& other) noexcept : Bn() { *this = std::move(other); }

Bn& Bn::operator=(Bn&& other) noexcept
{
    if (this != &other) {
        SecureWipe(m_val->dp, sizeof(m_val->dp));
        bn_copy(m_val, other.m_val);
        SecureWipe(other.m_val, sizeof(bn_st));
        bn_new(other.m_val);
        bn_zero(other.m_val);
    }
    return *this;
}
} // namespace util
} // namespace bls
