#pragma once

#include "eunet.h"

void usage();

struct SpoofEntry {
    Ip senderIp;
    Mac senderMac;
    Ip targetIp;
    Mac targetMac;
};

bool request_and_get_mac(pcap_t* pcap, Mac myMac, Ip myIp, Ip senderIp, Mac senderMac);
void arp_attack(pcap_t* handle, const Mac& sender_mac, const Ip& sender_ip, const Ip& target_ip, const Mac& my_mac);