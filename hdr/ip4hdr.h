# pragma once

#include "../eunet.h"

#pragma pack(push, 1)
struct Ip4Hdr {
    uint8_t v_hlen_;
    uint8_t tos_;
    uint16_t tlen_;
    uint16_t id_;
    uint16_t off_;
    uint8_t ttl_;
    uint8_t p_;
    uint16_t csum_;
    Ip sip_;
    Ip dip_;

    uint8_t v() { return (v_hlen_ & 0xF0) >> 4; }
    uint8_t hlen() { return v_hlen_ & 0x0F; }
    uint8_t tos() { return tos_; }
    uint16_t tlen() { return ntohs(tlen_); }
    uint16_t id() { return ntohs(id_); }
    uint16_t off() { return ntohs(off_); }
    uint8_t ttl() { return ttl_; }
    uint8_t p() { return p_; }
    uint16_t csum() { return ntohs(csum_); }
    Ip sip() { return ntohl(sip_); }
    Ip dip() { return ntohl(dip_); }

    // ip protocol types
    enum: uint8_t {
        TCP = 0x06,
        UDP = 0x11
    };
};
#pragma pack(pop)