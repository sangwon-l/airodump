#include <stdio.h>
#include <iostream>
#include <libnet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

using namespace std;
#define MAC_SIZE 6
#define ESS_BUF 256

#pragma pack(push, 1)
struct radiotap_header{
    uint8_t revision;
    uint8_t pad;
    uint16_t len;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beacon_frame{
    uint8_t type;
    uint8_t flags;
    uint16_t duration;
    uint8_t first_mac[MAC_SIZE];
    uint8_t second_mac[MAC_SIZE];
    uint8_t bssid[MAC_SIZE];
};
#pragma pack(pop)

struct radiotap_header* rhdr;
struct beacon_frame* bf;

#pragma pack(push, 1)
struct BEACON{
    uint8_t bssid[MAC_SIZE];
    int beacons;
    char essid[ESS_BUF];
    int essid_len;
};
#pragma pack(pop)

struct BEACON print_pkt[500];

void usage(){
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

int main(int argc, char *argv[]){
    if(argc != 2){
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s! - %s\n", dev, errbuf);
        return -1;
    }
    uint8_t BSSID[MAC_SIZE];
    uint8_t ESSID[ESS_BUF];
    int print_pkt_num = 0;
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){
           continue;
        }
        if (res == -1 || res == -2) {
           printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
           break;
        }
        rhdr=(struct radiotap_header*)(packet);
        int rhdr_len = rhdr->len;
        packet += rhdr_len;
        bf=(struct beacon_frame*)(packet);
        if(bf->type == 0x80){ // beacon frame
            memcpy(BSSID, bf->bssid, MAC_SIZE);
            packet += 36;
            int essid_len = packet[1];
            memcpy(ESSID, packet+2, essid_len);
            int pkt_flag = 0;
            for(int i = 0; i < print_pkt_num; i++){
                if(!memcmp(print_pkt[i].bssid, BSSID, MAC_SIZE)){
                    pkt_flag = 1; // this packet is redundant packet
                    print_pkt[i].beacons++;
                    break;
                }
            }
            if(pkt_flag == 0){ // this packet is new packet
                memcpy(print_pkt[print_pkt_num].bssid, BSSID, MAC_SIZE);
                print_pkt[print_pkt_num].beacons = 1;
                memcpy(print_pkt[print_pkt_num].essid, ESSID, essid_len);
                print_pkt[print_pkt_num].essid_len = essid_len;
                print_pkt_num++;
            }
        }
        printf(" BSSID              Beacons    ESSID\n");
        printf("----------------------------------------------------------------\n");
        for(int i = 0; i < print_pkt_num; i++){
            printf(" ");
            for(int j = 0; j < MAC_SIZE; j++){
                printf("%02X",print_pkt[i].bssid[j]);
                if(j != 5){
                    printf(":");
                }
            }
            printf("       ");
            printf("%d    ", print_pkt[i].beacons);
            int essid_flag = 0; //if essid == 0, flag is 1
            for(int j = 0 ; j < print_pkt[i].essid_len; j++){
                 if(print_pkt[i].essid[j] != 0){
                    essid_flag = 1;
                    break;
                 }
            }
            if(essid_flag == 1){
                for(int j = 0; j < print_pkt[i].essid_len; j++){
                    printf("%c", print_pkt[i].essid[j]);
                }
            }
            else{
                printf("<length:   %d>", print_pkt[i].essid_len);
            }
            printf("\n");
        }

        printf("----------------------------------------------------------------\n");
    }
    return 0;
}

