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

void    packet_format(const char *ip, int port, char *packet) {
    struct iphdr *ip_pkt = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    char ip_src[INET_ADDRSTRLEN];
    get_local_ip(ip_src);

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
    tcp->source = htons(1024 + rand() % 65535);  // Port source
    tcp->dest = htons(port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;
    //tcp->rst = 1;  // Flag RST activé
    tcp->syn = 1;  // Flag SYN
    tcp->window = htons(0);
    tcp->check = 0;  // Sera calculé plus tard
    tcp->urg_ptr = 0;

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

}

    //struct iphdr *ip = (struct iphdr *)packet;
    //struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    //char ip_src[INET_ADDRSTRLEN];
    //get_local_ip(ip_src);
    //printf("ip_src: %s\n", ip_src);
    //    // Remplissage de l'en-tête IP
    //ip->ihl = 5;  // Longueur de l'en-tête (5 * 4 = 20 octets)
    //ip->version = 4;  // IPv4
    //ip->tos = 0;
    //ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));  // Taille totale du paquet
    //ip->id = htons(54321);
    //ip->frag_off = 0;
    //ip->ttl = 64;
    //ip->protocol = IPPROTO_TCP;
    ////ip->saddr = INADDR_ANY;  // Adresse IP source
    //ip->saddr = inet_addr(ip_src); // Remplace par ton IP réelle
    //ip->daddr = inet_addr("8.8.8.8");  // Adresse IP destination
//
    //// Remplissage de l'en-tête TCP
    //tcp->source = htons(1024 + rand() % 65535);  // Port source
    //tcp->dest = htons(443);  // Port destination
    //tcp->seq = htonl(rand());  // Numéro de séquence aléatoire
    ////tcp->seq = htonl(0);
    //tcp->ack_seq = 0;
    //tcp->doff = 5;  // Longueur de l'en-tête TCP (5 * 4 = 20 octets)
    //tcp->syn = 1;  // Flag SYN
    ////tcp->window = htons(65535);
    //tcp->window = htons(14600);
    ////tcp->check = 0;  // Le checksum sera calculé plus tard
    //tcp->urg_ptr = 0;
//
    //// Calcul du checksum IP
    //ip->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

    //pseudo header est pour calculer le checksum tcp en prenant en compte les infos de l'en tete ip
    //struct pseudo_header psh;
    //psh.source_address = ip->saddr;
    //psh.dest_address = ip->daddr;
    //psh.placeholder = 0;
    //psh.protocol = IPPROTO_TCP;
    //psh.tcp_length = htons(sizeof(struct tcphdr));
//
    //char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    //memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    //memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
//
//
    //tcp->check = checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));
    // Informations sur la destination