# pragma once

#include "eunet.h"

#pragma pack(push, 1)
struct EthHdr {
    Mac dmac_;
    Mac smac_;
    uint16_t type_;

    Mac dmac() { return dmac_; }
    Mac smac() { return smac_; }
    uint16_t type() { return ntohs(type_); }

    // ethernet types
    enum: uint16_t {
      IP4 = 0x0800,
      ARP = 0x0806,
      IP6 = 0x86DD
	};
};
#pragma pack(pop)