// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.MIT or https://opensource.org/license/MIT

#include "wipe.h"

#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace bls {
namespace util {
void SecureWipe(void* ptr, size_t len) noexcept
{
    if (ptr == nullptr || len == 0) {
        return;
    }
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#else
    std::memset(ptr, 0, len);
    // A barrier the compiler may not reorder across, so the memset above cannot
    // be dropped as a dead store on a buffer nothing reads again.
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}
} // namespace util
} // namespace bls
