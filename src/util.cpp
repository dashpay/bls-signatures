// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.MIT or https://opensource.org/license/MIT

#include "util.hpp"

extern "C" {
#include "relic.h"
}

namespace bls {
void Util::Hash256(uint8_t* output, const uint8_t* message,
                   size_t messageLen) {
    md_map_sh256(output, message, messageLen);
}

std::string Util::HexStr(const uint8_t* data, size_t len) {
    std::stringstream s;
    s << std::hex;
    for (size_t i=0; i < len; ++i)
        s << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    return s.str();
}

std::string Util::HexStr(const std::vector<uint8_t> &data) {
    std::stringstream s;
    s << std::hex;
    for (size_t i=0; i < data.size(); ++i)
        s << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    return s.str();
}

uint8_t Util::char2int(const char input) {
    if(input >= '0' && input <= '9')
        return input - '0';
    if(input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if(input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}

std::vector<uint8_t> Util::HexToBytes(const std::string hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Invalid input string, length must be multple of 2");
    }
    std::vector<uint8_t> ret = std::vector<uint8_t>();
    size_t start_at = 0;
    if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) {
        start_at = 2;
    }

    for (size_t i = start_at; i < hex.size(); i += 2) {
        ret.push_back(char2int(hex[i]) * 16 + char2int(hex[i+1]));
    }
    return ret;
}

void Util::IntToFourBytes(uint8_t* result,
                           const uint32_t input) {
    for (size_t i = 0; i < 4; i++) {
        result[3 - i] = (input >> (i * 8));
    }
}

uint32_t Util::FourBytesToInt(const uint8_t* bytes) {
    uint32_t sum = 0;
    for (size_t i = 0; i < 4; i++) {
        uint32_t addend = static_cast<uint32_t>(bytes[i]) << (8 * (3 - i));
        sum += addend;
    }
    return sum;
}

bool Util::HasOnlyZeros(const Bytes& bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](uint8_t byte){ return byte == 0x00; });
}
} // namespace bls
