
#include "pkt.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "ip.h"
#include "iphdr.h"
#include "tcphdr.h"
#include <string>

unsigned char* get_data(unsigned char* buf, int size){
    Iphdr* ip = (Iphdr*)buf;
    unsigned char* data  = buf + ip->get_IP_length()*4;
    return data;

}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

/* returns packet id */
u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d\n", ret);
        // dump(data, ret);

    }


    fputc('\n', stdout);

    return id;
}


int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    bool bad_host = false;
    u_int32_t id = print_pkt(nfa);
    unsigned char* pkt;
    int ret = nfq_get_payload(nfa, &pkt);
    std::string host((char*)data);

    Iphdr* ip = (Iphdr*) pkt;
    uint8_t protocol = ip->protocol;
    int ip_size = ip->get_IP_length();
    printf("ip_size : %d\n", ip_size);
    printf("\n\nprotocol : %d\n\n", protocol);


    if (ret > 0 && protocol == 6){ //tcp
        pkt = pkt + ip_size;


        Tcphdr* tcphdr = (Tcphdr*)pkt;
        int tcp_size = tcphdr->get_tcp_len();
        printf("HHHHHHHHHHHHHHHHHH%d\n", tcp_size);
        // dump(pkt, tcp_size);


        unsigned char* http = pkt + tcp_size;
        int http_size = ret - ip_size - tcp_size;

        if(http_size > 0){
            // dump(http, http_size);
            std::string http_payload((char*)http, http_size);
            printf("%s\n", http_payload.c_str());


            size_t pos = http_payload.find("Host: ");
            if(pos != std::string::npos){
                size_t end = http_payload.find("\r\n", pos);
                std::string host_ = http_payload.substr(pos, end - pos);
                printf(">>> %s\n", host_.c_str());

                std::string host_line = http_payload.substr(pos + 6, end - (pos + 6));
                printf(">>>>>>>>>>>>>>>>%s\n", host_line.c_str());

                if(host_line == host){
                    printf("CATCH!!!!!!!!!\n");
                    bad_host = true;

                }


            }
        }

    }
    else{ //no tcp
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }





    printf("entering callback\n");

    if(bad_host){
        printf("HEY!!!! BAD SITE NONO \n ");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    //new buffer -> bufsize, buf => packet modify
}
