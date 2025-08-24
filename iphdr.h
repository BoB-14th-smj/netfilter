#pragma once
#include <netinet/in.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include "ip.h"
#include "iphdr.h"
#pragma pack(push,1)


struct Iphdr{
    uint8_t version_legnth;
    uint8_t service_type;

    uint16_t tolal_length;
    uint16_t identification;
    uint16_t fragment_offset : 13;
    uint16_t flags : 3;


    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;

    Ip s_ip_;
    Ip d_ip_;

    Ip src() { return Ip(ntohl(s_ip_)) ;};
    Ip dst() { return Ip(ntohl(d_ip_)); };

    uint8_t get_IP_length(){
        // printf("why?????? %x\n", version_legnth & 0x0F);
        return (version_legnth & 0x0F) * 4 ;}
    uint8_t get_protocol() { return protocol;}


};
