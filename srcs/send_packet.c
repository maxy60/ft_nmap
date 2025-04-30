#include "ft_nmap.h"

uint16_t checksum(void *b, int len) {    
    uint16_t *buf = b;
    uint32_t sum = 0;
    uint16_t result;

    // Additionne chaque mot de 16 bits
    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    // Si la longueur est impaire, ajoute l'octet restant
    if (len == 1)
        sum += *(uint8_t *)buf;

    // Ajoute les bits de report du haut vers le bas
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Complément à un
    result = ~sum;

    return result;
}

void    send_packet(const char *ip, int port, int socket, t_scan_type scan) {
    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE); //tmp
    struct iphdr *ip_pkt = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    char ip_src[INET_ADDRSTRLEN];
    get_local_ip(ip_src);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(ip);

    // Remplissage de l'en-tête IP
    ip_pkt->ihl = 5;        // Longueur de l'en-tête (5 * 4 = 20 octets)
    ip_pkt->version = 4;    // IPv4
    ip_pkt->tos = 0;
    ip_pkt->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_pkt->id = htons(54321);
    ip_pkt->frag_off = 0;
    ip_pkt->ttl = 64;
    ip_pkt->protocol = IPPROTO_TCP;
    ip_pkt->saddr = inet_addr(ip_src);
    ip_pkt->daddr = inet_addr(ip);

    // Calcul du checksum IP
    ip_pkt->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

    // Remplissage de l'en-tête TCP
    tcp->source = htons(5000 + scan);  // Port source
    tcp->dest = htons(port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;
    switch (scan) {
        case SCAN_SYN:
            tcp->th_flags = TH_SYN;      // 0x02
            break;
        case SCAN_ACK:
            tcp->th_flags = TH_ACK;      // 0x10
            break;
        case SCAN_NULL:
            tcp->th_flags = 0;           // aucun bit activé
            break;
        case SCAN_FIN:
            tcp->th_flags = TH_FIN;      // 0x01
            break;
        case SCAN_XMAS:
            tcp->th_flags = TH_FIN | TH_PUSH | TH_URG;  // 0x01 | 0x08 | 0x20 = 0x29
            break;
        case SCAN_UDP:
            // UDP 
            break;
    }
    tcp->window = htons(0);
    tcp->urg_ptr = 0;


    //for calculate checksum
    struct pseudo_header psh;
    psh.source_address = ip_pkt->saddr;
    psh.dest_address = ip_pkt->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));


    tcp->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));
    if (sendto(socket, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        return ; //gerer l'erreur
    }
}