#pragma once

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr ethHdr_;
    ArpHdr arpHdr_;
    uint16_t padding_{0};

    void init(Mac dmac, Mac smac, uint16_t operation, Mac senderMac, Ip senderIp, Mac targetMac, Ip targetIp);
};
#pragma pack(pop)