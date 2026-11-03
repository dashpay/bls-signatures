// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.MIT or https://opensource.org/license/MIT

#include "secure.h"

#include <catch2/catch.hpp>

#include <algorithm>
#include <array>
#include <cstdint>

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
