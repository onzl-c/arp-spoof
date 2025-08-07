#include "spoof.h"

int main(int argc, char* argv[]) {
    // 1. 인자 개수 검사
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    // 2. pcap 핸들 열기
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    printf("Device %s opened successfully.\n", dev);

    // 3. 내 MAC/IP 주소 얻기
    Mac myMac;
    if (!getMyMac(dev, myMac.mac_)) {
        fprintf(stderr, "Failed to get MAC address for %s\n", dev);
        return -1;
    }
    Ip myIp = getMyIp(dev);

    // 4. 스푸핑 쌍 목록 생성
    vector<SpoofEntry> entries;
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]);
        Ip targetIp(argv[i+1]);
        
        // 4-1. sender의 MAC 주소 획득
        Mac senderMac;
        if (!request_and_get_mac(pcap, myMac, myIp, senderIp, senderMac)) {
            printf("Failed to get MAC for sender: %s\n", string(senderIp).c_str());
            continue;
        }
        
        // 4-2. target의 MAC 주소 획득
        Mac targetMac;
        if (!request_and_get_mac(pcap, myMac, myIp, targetIp, targetMac)) {
            printf("Failed to get MAC for target: %s\n", string(targetIp).c_str());
            continue;
        }

        // 4-3. 스푸핑 엔트리 추가
        entries.push_back({senderIp, senderMac, targetIp, targetMac});
    }
    
    // 4-4. 스푸핑 엔트리가 없다면 종료
    if (entries.empty()) {
        fprintf(stderr, "No valid sender-target pairs found.\n");
        pcap_close(pcap);
        return -1;
    }

    // 5. 스푸핑 공격
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res < 0) return false;

        // 5-1. 주기적 감염

        // 5-2. 패킷 relay
    }

    pcap_close(pcap);
    return 0;
}