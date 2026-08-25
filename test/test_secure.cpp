// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.MIT or https://opensource.org/license/MIT

#include "bls.hpp"
#include "secure.h"

#include <catch2/catch.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <thread>
#include <type_traits>
#include <vector>

namespace {
alignas(std::max_align_t) uint8_t g_arena[4096];
size_t g_arenaUsed{0};

void* ArenaAlloc(size_t nBytes)
{
    constexpr size_t nAlign = alignof(std::max_align_t);
    const size_t nStep = (nBytes + nAlign - 1) & ~(nAlign - 1);
    if (nStep > sizeof(g_arena) - g_arenaUsed) {
        return nullptr;
    }
    void* pBlock = g_arena + g_arenaUsed;
    g_arenaUsed += nStep;
    return pBlock;
}

void ArenaFree(void*) {}

struct ArenaGuard {
    ArenaGuard()
    {
        bls::util::GetSecureAllocator(&m_pfnAlloc, &m_pfnFree);
        g_arenaUsed = 0;
        bls::util::SetSecureAllocator(ArenaAlloc, ArenaFree);
    }

    ~ArenaGuard()
    {
        if (m_pfnAlloc != nullptr && m_pfnFree != nullptr) {
            bls::util::SetSecureAllocator(m_pfnAlloc, m_pfnFree);
        }
    }

private:
    bls::Util::SecureAllocCallback m_pfnAlloc{nullptr};
    bls::Util::SecureFreeCallback m_pfnFree{nullptr};
};
} // anonymous namespace

TEST_CASE("util::SecureWipe clears a buffer")
{
    std::array<uint8_t, 32> buf;
    buf.fill(0xff);
    bls::util::SecureWipe(buf.data(), buf.size());
    REQUIRE(std::all_of(buf.begin(), buf.end(), [](uint8_t b) {
        return b == 0;
    }));

    // Degenerate arguments are ignored rather than faulting.
    bls::util::SecureWipe(nullptr, 16);
    bls::util::SecureWipe(buf.data(), 0);
}

TEST_CASE("Secure allocation is safe to use from several threads")
{
    // The callbacks are reached from every thread that holds a key, so this is
    // here to be run under a sanitizer rather than to assert an outcome.
    std::vector<std::thread> threads;

    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([] {
            for (int j = 0; j < 250; ++j) {
                auto* p = bls::util::SecAlloc<uint8_t>(64);
                std::memset(p, 0x7e, 64);
                bls::util::SecFree(p, 64);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    SUCCEED("no allocation raced another");
}

TEST_CASE("The secure allocator is never called through a null")
{
    REQUIRE_THROWS_AS(bls::util::SetSecureAllocator(nullptr, std::free),
                      std::invalid_argument);
    REQUIRE_THROWS_AS(bls::util::SetSecureAllocator(std::malloc, nullptr),
                      std::invalid_argument);

    // Rejecting the bad pair must not have disturbed the installed one.
    auto* p = bls::util::SecAlloc<uint8_t>(32);
    REQUIRE(p != nullptr);
    bls::util::SecFree(p, 32);
}

TEST_CASE("Secure allocation failure throws rather than returning null")
{
    // The raw SecAlloc callers do not check for null, so a count that does not
    // fit in a size_t once scaled by the object size has to throw rather than
    // wrap into a small allocation the caller then writes past.
    REQUIRE_THROWS_AS(bls::util::SecAlloc<uint64_t>(
        std::numeric_limits<size_t>::max() / 4), std::bad_alloc);
    REQUIRE_THROWS_AS(bls::util::SecAlloc<uint32_t>(
        std::numeric_limits<size_t>::max()), std::bad_alloc);
}

namespace {
size_t g_nNullFrees{0};

void* NullOnZeroAlloc(size_t nBytes)
{
    return nBytes == 0 ? nullptr : std::malloc(nBytes);
}

void CountingFree(void* ptr)
{
    if (ptr == nullptr) {
        ++g_nNullFrees;
    }
    std::free(ptr);
}
} // anonymous namespace

TEST_CASE("Secure allocation handles malloc edge cases")
{
    bls::Util::SecureAllocCallback pfnAlloc{nullptr};
    bls::Util::SecureFreeCallback pfnFree{nullptr};
    bls::util::GetSecureAllocator(&pfnAlloc, &pfnFree);
    bls::util::SetSecureAllocator(NullOnZeroAlloc, CountingFree);

    // A zero-length request is not a failure even if the callback says null.
    void* p = nullptr;
    REQUIRE_NOTHROW(p = bls::util::SecMalloc(0));
    REQUIRE(p != nullptr);
    bls::util::SecFree(p, 0);

    g_nNullFrees = 0;
    bls::util::SecFree(nullptr, 16);
    REQUIRE(g_nNullFrees == 0);

    bls::util::SetSecureAllocator(pfnAlloc, pfnFree);
}

TEST_CASE("A private key has value semantics and clears itself")
{
    SECTION("Destruction leaves nothing behind")
    {
        // The key's scalar goes back through SecFree, which the installed
        // allocator need not clear, so the extent has to travel with it.
        std::memset(g_arena, 0xcd, sizeof(g_arena));
        {
            ArenaGuard guard;
            const std::vector<uint8_t> skBytes(
                bls::PrivateKey::PRIVATE_KEY_SIZE, 0x2a);
            bls::PrivateKey sk = bls::PrivateKey::FromByteVector(skBytes);
            REQUIRE(std::any_of(g_arena, g_arena + sizeof(blst_scalar),
                                [](uint8_t b) { return b != 0 && b != 0xcd; }));
        }

        REQUIRE(std::all_of(g_arena, g_arena + sizeof(blst_scalar),
                            [](uint8_t b) { return b == 0; }));
    }
}

TEST_CASE("util::SecVector allocates through the secure allocator")
{
    static_assert(std::is_same<bls::util::SecVector<uint32_t>::allocator_type,
                               bls::util::SecureAllocator<uint32_t>>::value,
                  "SecVector has to carry the secure allocator");

    // Growth reallocates, so this walks allocate and deallocate rather than
    // only the one reservation a sized construction would make.
    bls::util::SecVector<uint32_t> words;
    for (uint32_t i = 0; i < 64; ++i) {
        words.push_back(i);
    }

    REQUIRE(words.size() == 64);
    REQUIRE(words.front() == 0);
    REQUIRE(words.back() == 63);
}

TEST_CASE("Secure release clears the bytes before handing them back")
{
    SECTION("util::SecVector, through the allocator")
    {
        std::memset(g_arena, 0xcd, sizeof(g_arena));
        {
            ArenaGuard guard;
            bls::util::SecVector<uint8_t> secret(64);
            std::fill(secret.begin(), secret.end(), 0xab);
        }
        REQUIRE(std::none_of(g_arena, g_arena + 64, [](uint8_t b) {
            return b == 0xab;
        }));
        REQUIRE(std::all_of(g_arena, g_arena + 64, [](uint8_t b) {
            return b == 0;
        }));
    }
}
