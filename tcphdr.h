#pragma once
#include <cstdint>
#include <netinet/in.h>
#include <stdint.h>
#include <pcap/pcap.h>
// #pragma pack(push,1)


struct Tcphdr{
    uint16_t src;
    uint16_t dst;

    uint32_t seq_num;
    uint32_t ack_num;

    uint8_t hlen_reserved;
    uint8_t flags;

    uint16_t win_size;
    uint16_t checksum;
    uint16_t urgent_pointer;


    uint8_t get_tcp_len() { return (hlen_reserved >> 4) * 4; ;};

    bool is_fin() const { return flags & 0x01; }
    bool is_syn() const { return flags & 0x02; }
    bool is_rst() const { return flags & 0x04; }
    bool is_psh() const { return flags & 0x08; }
    bool is_ack() const { return flags & 0x10; }
    bool is_urg() const { return flags & 0x20; }
    bool is_ece() const { return flags & 0x40; }
    bool is_cwr() const { return flags & 0x80; }



};
