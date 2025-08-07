#include "etharppacket.h"

void EthArpPacket::init(Mac dmac, Mac smac, uint16_t operation, Mac senderMac, Ip senderIp, Mac targetMac, Ip targetIp) {
    ethHdr_.dmac_ = dmac;
    ethHdr_.smac_ = smac;
    ethHdr_.type_ = htons(EthHdr::ARP);

    arpHdr_.hrd_ = htons(ArpHdr::ETHERNET);
    arpHdr_.pro_ = htons(EthHdr::IP4);
    arpHdr_.hlen_ = Mac::SIZE;
    arpHdr_.plen_ = Ip::SIZE;
    arpHdr_.op_ = htons(operation);
    arpHdr_.smac_ = senderMac;
    arpHdr_.sip_ = htonl(senderIp);
    arpHdr_.tmac_ = targetMac;
    arpHdr_.tip_ = htonl(targetIp);
}