// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.MIT or https://opensource.org/license/MIT

#include "hdkeys.hpp"
#include "secure.h"

namespace bls {
PrivateKey HDKeys::KeyGen(const std::vector<uint8_t>& seed)
{
    return KeyGen(Bytes(seed));
}

PrivateKey HDKeys::KeyGen(const Bytes& seed)
{
    // KeyGen
    // 1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
    // 2. OKM = HKDF-Expand(PRK, keyInfo || I2OSP(L, 2), L)
    // 3. SK = OS2IP(OKM) mod r
    // 4. return SK

    const uint8_t info[1] = {0};
    const size_t infoLen = 0;

    // Required by the ietf spec to be at least 32 bytes
    if (seed.size() < 32) {
        throw std::invalid_argument("Seed size must be at least 32 bytes");
    }

    blst_scalar* skBn = util::SecAlloc<blst_scalar>(1);
    blst_keygen_v3(skBn, seed.begin(), seed.size(), info, infoLen);
    uint8_t* skBytes = util::SecAlloc<uint8_t>(32);
    blst_bendian_from_scalar(skBytes, skBn);

    PrivateKey k = PrivateKey::FromBytes(Bytes(skBytes, 32));

    util::SecFree(skBn, sizeof(blst_scalar));
    util::SecFree(skBytes, 32);

    return k;
}

void HDKeys::IKMToLamportSk(
    uint8_t* outputLamportSk,
    const uint8_t* ikm,
    size_t ikmLen,
    const uint8_t* salt,
    size_t saltLen)
{
    // Expands the ikm to 255*HASH_LEN bytes for the lamport sk
    const uint8_t info[1] = {0};
    HKDF256::ExtractExpand(
        outputLamportSk,
        HASH_LEN * 255,
        ikm,
        ikmLen,
        salt,
        saltLen,
        info,
        0);
}

void HDKeys::ParentSkToLamportPK(
    uint8_t* outputLamportPk,
    const PrivateKey& parentSk,
    uint32_t index)
{
    uint8_t* salt = util::SecAlloc<uint8_t>(4);
    uint8_t* ikm = util::SecAlloc<uint8_t>(HASH_LEN);
    uint8_t* notIkm = util::SecAlloc<uint8_t>(HASH_LEN);
    uint8_t* lamport0 = util::SecAlloc<uint8_t>(HASH_LEN * 255);
    uint8_t* lamport1 = util::SecAlloc<uint8_t>(HASH_LEN * 255);

    Util::IntToFourBytes(salt, index);
    parentSk.Serialize(ikm);

    for (size_t i = 0; i < HASH_LEN; i++) {  // Flips the bits
        notIkm[i] = ikm[i] ^ 0xff;
    }

    HDKeys::IKMToLamportSk(lamport0, ikm, HASH_LEN, salt, 4);
    HDKeys::IKMToLamportSk(lamport1, notIkm, HASH_LEN, salt, 4);

    uint8_t* lamportPk = util::SecAlloc<uint8_t>(HASH_LEN * 255 * 2);

    for (size_t i = 0; i < 255; i++) {
        Util::Hash256(
            lamportPk + i * HASH_LEN, lamport0 + i * HASH_LEN, HASH_LEN);
    }

    for (size_t i = 0; i < 255; i++) {
        Util::Hash256(
            lamportPk + 255 * HASH_LEN + i * HASH_LEN,
            lamport1 + i * HASH_LEN,
            HASH_LEN);
    }
    Util::Hash256(outputLamportPk, lamportPk, HASH_LEN * 255 * 2);

    util::SecFree(salt, 4);
    util::SecFree(ikm, HASH_LEN);
    util::SecFree(notIkm, HASH_LEN);
    util::SecFree(lamport0, HASH_LEN * 255);
    util::SecFree(lamport1, HASH_LEN * 255);
    util::SecFree(lamportPk, HASH_LEN * 255 * 2);
}

PrivateKey HDKeys::DeriveChildSk(const PrivateKey& parentSk, uint32_t index)
{
    uint8_t* lamportPk = util::SecAlloc<uint8_t>(HASH_LEN);
    HDKeys::ParentSkToLamportPK(lamportPk, parentSk, index);
    std::vector<uint8_t> lamportPkVector(lamportPk, lamportPk + HASH_LEN);
    PrivateKey child = HDKeys::KeyGen(lamportPkVector);
    util::SecFree(lamportPk, HASH_LEN);
    return child;
}

PrivateKey HDKeys::DeriveChildSkUnhardened(
    const PrivateKey& parentSk,
    uint32_t index)
{
    uint8_t* buf = util::SecAlloc<uint8_t>(G1Element::SIZE + 4);
    uint8_t* digest = util::SecAlloc<uint8_t>(HASH_LEN);
    memcpy(
        buf, parentSk.GetG1Element().Serialize().data(), G1Element::SIZE);
    Util::IntToFourBytes(buf + G1Element::SIZE, index);
    Util::Hash256(digest, buf, G1Element::SIZE + 4);

    PrivateKey ret = PrivateKey::Aggregate(
        {parentSk, PrivateKey::FromBytes(Bytes(digest, HASH_LEN), true)});

    util::SecFree(buf, G1Element::SIZE + 4);
    util::SecFree(digest, HASH_LEN);
    return ret;
}

G1Element HDKeys::DeriveChildG1Unhardened(
    const G1Element& pk,
    uint32_t index)
{
    uint8_t* buf = util::SecAlloc<uint8_t>(G1Element::SIZE + 4);
    uint8_t* digest = util::SecAlloc<uint8_t>(HASH_LEN);
    memcpy(buf, pk.Serialize().data(), G1Element::SIZE);

    Util::IntToFourBytes(buf + G1Element::SIZE, index);
    Util::Hash256(digest, buf, G1Element::SIZE + 4);

    blst_scalar nonce;
    // The digest is big-endian; upstream chia loaded it as little-endian,
    // which only worked because operator* reversed the bytes again.
    blst_scalar_from_bendian(&nonce, digest);

    util::SecFree(buf, G1Element::SIZE + 4);
    util::SecFree(digest, HASH_LEN);

    G1Element gen = G1Element::Generator();

    return pk + (gen * nonce);
}

G2Element HDKeys::DeriveChildG2Unhardened(
    const G2Element& pk,
    uint32_t index)
{
    uint8_t* buf = util::SecAlloc<uint8_t>(G2Element::SIZE + 4);
    uint8_t* digest = util::SecAlloc<uint8_t>(HASH_LEN);
    memcpy(buf, pk.Serialize().data(), G2Element::SIZE);
    Util::IntToFourBytes(buf + G2Element::SIZE, index);
    Util::Hash256(digest, buf, G2Element::SIZE + 4);

    blst_scalar nonce;
    // The digest is big-endian; upstream chia loaded it as little-endian,
    // which only worked because operator* reversed the bytes again.
    blst_scalar_from_bendian(&nonce, digest);

    util::SecFree(buf, G2Element::SIZE + 4);
    util::SecFree(digest, HASH_LEN);

    G2Element gen = G2Element::Generator();
    return pk + gen * nonce;
}
} // namespace bls
