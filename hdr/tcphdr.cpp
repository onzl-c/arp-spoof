#include "tcphdr.h"

Buf TcpHdr::parseData(Ip4Hdr* ipHdr, TcpHdr* tcpHdr) {
    Buf res;
    res.size_ = ipHdr->tlen() - ipHdr->hlen() * 4 - tcpHdr->off() * 4;
    if (res.size_ > 0)
        res.data_ = reinterpret_cast<const uint8_t*>(tcpHdr) + tcpHdr->off() * 4;
    else
        res.data_ = nullptr;
    return res;
}