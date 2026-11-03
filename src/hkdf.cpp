// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.MIT or https://opensource.org/license/MIT

#include "hkdf.hpp"
#include "secure.h"

namespace bls {
void HKDF256::Extract(uint8_t* prk_output, const uint8_t* salt, const size_t saltLen, const uint8_t* ikm, const size_t ikm_len) {
    // assert(saltLen == 4);  // Used for EIP2333 key derivation
    // assert(ikm_len == 32);  // Used for EIP2333 key derivation
    // Hash256 used as the hash function (sha256)
    // PRK Output is 32 bytes (HashLen)
    Util::md_hmac(prk_output, ikm, ikm_len, salt, saltLen);
}

void HKDF256::Expand(uint8_t* okm, size_t L, const uint8_t* prk, const uint8_t* info, const size_t infoLen) {
    assert(L <= 255 * HASH_LEN); // L <= 255 * HashLen
    size_t N = (L + HASH_LEN - 1) / HASH_LEN; // Round up
    size_t bytesWritten = 0;

    uint8_t* T = util::SecAlloc<uint8_t>(HASH_LEN);
    uint8_t* hmacInput1 = util::SecAlloc<uint8_t>(infoLen + 1);
    uint8_t* hmacInput = util::SecAlloc<uint8_t>(HASH_LEN + infoLen + 1);

    assert(N >= 1 && N <= 255);

    for (size_t i = 1; i <= N; i++) {
        if (i == 1) {
            memcpy(hmacInput1, info, infoLen);
            hmacInput1[infoLen] = i;
            Util::md_hmac(T, hmacInput1, infoLen + 1, prk, HASH_LEN);
        } else {
            memcpy(hmacInput, T, HASH_LEN);
            memcpy(hmacInput + HASH_LEN, info, infoLen);
            hmacInput[HASH_LEN + infoLen] = i;
            Util::md_hmac(T, hmacInput, HASH_LEN + infoLen + 1, prk, HASH_LEN);
        }
        size_t to_write = L - bytesWritten;
        if (to_write > HASH_LEN) {
            to_write = HASH_LEN;
        }
        assert (to_write > 0 && to_write <= HASH_LEN);
        memcpy(okm + bytesWritten, T, to_write);
        bytesWritten += to_write;
    }
    util::SecFree(T, HASH_LEN);
    util::SecFree(hmacInput1, infoLen + 1);
    util::SecFree(hmacInput, HASH_LEN + infoLen + 1);
    assert(bytesWritten == L);
}

void HKDF256::ExtractExpand(uint8_t* output, size_t outputLen,
                          const uint8_t* key, size_t keyLen,
                          const uint8_t* salt, size_t saltLen,
                          const uint8_t* info, size_t infoLen) {
    uint8_t* prk = util::SecAlloc<uint8_t>(HASH_LEN);
    HKDF256::Extract(prk, salt, saltLen, key, keyLen);
    HKDF256::Expand(output, outputLen, prk, info, infoLen);
    util::SecFree(prk, HASH_LEN);
}
} // namespace bls
