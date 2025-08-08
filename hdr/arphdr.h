# pragma once

#include "../eunet.h"

#pragma pack(push, 1)
struct ArpHdr {
    uint16_t hrd_;
    uint16_t pro_;
    uint8_t hlen_;
    uint8_t plen_;
    uint16_t op_;
    Mac smac_;   
    Ip sip_;
    Mac tmac_;
    Ip tip_;

    uint16_t hrd() { return ntohs(hrd_); }
    uint16_t pro() { return ntohs(pro_); }
    uint8_t hlen() { return hlen_; }
    uint8_t plen() { return plen_; }
    uint16_t op() { return ntohs(op_); }
    Mac smac() { return smac_; }
    Ip sip() { return ntohl(sip_); }
    Mac tmac() { return tmac_; }
    Ip tip() { return ntohl(tip_); }

    // network link protocol
    enum: uint16_t {
        ETHERNET = 1
    };

    // opcode
    enum: uint16_t {
        REQUEST = 1,
        REPLY = 2
    };
};
#pragma pack(pop)