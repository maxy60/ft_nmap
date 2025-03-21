#include <ft_nmap.h>

void analyse_packet(char *buffer) {
    struct iphdr *ip_resp = (struct iphdr *)buffer;
    struct tcphdr *tcp_resp = (struct tcphdr *)(buffer + (ip_resp->ihl * 4));

    struct in_addr src, dest;
    src.s_addr = ip_resp->saddr;
    dest.s_addr = ip_resp->daddr;

    printf("\n--- 📦 Paquet reçu ---\n");
    printf("📍 IP Source: %s\n", inet_ntoa(src));
    printf("🎯 IP Destination: %s\n", inet_ntoa(dest));
    printf("📏 Taille totale: %d octets\n", ntohs(ip_resp->tot_len));
    printf("🛰  TTL: %d\n", ip_resp->ttl);
    printf("📡 Protocole: %d (TCP = 6, UDP = 17, ICMP = 1)\n", ip_resp->protocol);

    if (ip_resp->protocol == IPPROTO_TCP) {
        printf("\n--- 🔧 En-tête TCP ---\n");
        printf("📌 Port source: %d\n", ntohs(tcp_resp->source));
        printf("🎯 Port destination: %d\n", ntohs(tcp_resp->dest));
        printf("🔢 Numéro de séquence: %u\n", ntohl(tcp_resp->seq));
        printf("📩 Numéro d'acquittement: %u\n", ntohl(tcp_resp->ack_seq));

        printf("\n--- 🚩 Flags TCP ---\n");
        printf("SYN: %d | ACK: %d | RST: %d | FIN: %d | PSH: %d | URG: %d\n",
               tcp_resp->syn, tcp_resp->ack, tcp_resp->rst,
               tcp_resp->fin, tcp_resp->psh, tcp_resp->urg);
        
        printf("\n--- 📦 Payload ---\n");
        int ip_header_len = ip_resp->ihl * 4;
        int tcp_header_len = tcp_resp->doff * 4;
        int payload_offset = ip_header_len + tcp_header_len;
        int payload_size = ntohs(ip_resp->tot_len) - payload_offset;
        
        if (payload_size > 0) {
            printf("📄 Contenu: ");
            for (int i = payload_offset; i < ntohs(ip_resp->tot_len); i++) {
                printf("%02X ", (unsigned char)buffer[i]);
            }
            printf("\n");
        } else {
            printf("🚫 Pas de payload\n");
        }
    }
}