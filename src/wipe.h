// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.MIT or https://opensource.org/license/MIT

#ifndef DASHBLS_WIPE_H
#define DASHBLS_WIPE_H

#include <cstddef>

namespace bls {
namespace util {
/**
 * Overwrites a buffer that held a secret with zeroes.
 *
 * A memset behind a barrier, as Bitcoin Core's memory_cleanse does it, so the
 * store is not dropped on a buffer nothing reads again. A null pointer or a
 * zero length is ignored.
 *
 * See "Dead Store Elimination (Still) Considered Harmful", Yang et al.,
 * USENIX Security 2017.
 *
 * @param   ptr  Start of the buffer to clear.
 * @param   len  How many bytes to clear.
 */
void SecureWipe(void* ptr, size_t len) noexcept;
} // namespace util
} // namespace bls

#endif // DASHBLS_WIPE_H
