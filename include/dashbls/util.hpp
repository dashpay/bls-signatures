// Copyright 2020 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SRC_BLSUTIL_HPP_
#define SRC_BLSUTIL_HPP_

#include "relic_conf.h"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

extern "C" {
#include "relic.h"
}

#include <algorithm>
#include <array>
#include <cstddef>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace bls {
class BLS;

class Bytes {
    const uint8_t* pData;
    const size_t nSize;

public:
    Bytes(const uint8_t* pDataIn, const size_t nSizeIn)
        : pData(pDataIn), nSize(nSizeIn)
    {
    }
    Bytes(const std::vector<uint8_t>& vecBytes)
        : pData(vecBytes.data()), nSize(vecBytes.size())
    {
    }
    template <size_t N>
    Bytes(const std::array<uint8_t, N>& a)
        : pData(a.data()), nSize(N)
    {
    }

    inline const uint8_t* begin() const { return pData; }
    inline const uint8_t* end() const { return pData + nSize; }

    inline size_t size() const { return nSize; }

    const uint8_t& operator[](const int nIndex) const { return pData[nIndex]; }
};

class Util {
 public:
    typedef void *(*SecureAllocCallback)(size_t);
    typedef void (*SecureFreeCallback)(void*);
 public:
    static void Hash256(uint8_t* output, const uint8_t* message,
                        size_t messageLen);

    static std::string HexStr(const uint8_t* data, size_t len);

    static std::string HexStr(const std::vector<uint8_t> &data);

    /*
     * Converts one hex character to an int.
     */
    static uint8_t char2int(const char input);

    /*
     * Converts a hex string into a vector of bytes.
     */
    static std::vector<uint8_t> HexToBytes(const std::string hex);

    /*
     * Converts a 32 bit int to bytes.
     */
    static void IntToFourBytes(uint8_t* result,
                               const uint32_t input);

    /*
     * Converts a byte array to a 32 bit int.
     */
    static uint32_t FourBytesToInt(const uint8_t* bytes);

    static bool HasOnlyZeros(const Bytes& bytes);

};
} // end namespace bls
#endif  // SRC_BLSUTIL_HPP_
