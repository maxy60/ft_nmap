#include "ft_nmap.h"

static t_nmap g_nmap = {
	.sockfd = 0,
	.dest_addr = NULL,
	.dest = {
		.sin_family = AF_INET,
		.sin_port = 0
	}
};

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

//have to define if we need fct
//int parse_ip();

int main(int ac, char **av) {
    if(ac == 1 || strcmp(av[1], "--help") == 0) {
        printf("ft_nmap [OPTIONS]\n --help     Print this help screen\n --ports    ports to scan (ex: 1-10 or 1,2,3 or 1,5-15)\n --ip       address to scan in dot format\n --file     File name containing IP addresses to scan,\n --speedup  [250 max] number of parallel threads to use\n --scan     SYN/NULL/FIN/XMAS/ACK/UDP\n");
        return 0;
    }
    int i = 0;
    int is_ip = 0;
    while (i != ac) {
        if (strcmp(av[i], "--ip") == 0 && i < ac) {
            struct addrinfo hints = {.ai_family = AF_INET};
            struct addrinfo *res;
            if (getaddrinfo(av[i + 1], NULL, &hints, &res))
                return 1;
            printf("trest\n");
            g_nmap.dest_addr = av[i + 1];
            g_nmap.dest.sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
            is_ip += 1;
            printf("des_addr = %s\n", g_nmap.dest_addr);
        }
        i++;
    }

    if(is_ip == 1) { //just for use is_ip and compile easy
        printf("is_ip = %d\n", is_ip);
    }
    else {
        printf("prblm\n");
        return -1;
    }
    int sock_tcp;
    //int sock_udp;
    //int sock_icmp;
    struct sockaddr_in dest;
    char packet[PACKET_SIZE];


    // Création du socket brut
    sock_tcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    //sock_udp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    //sock_icmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_tcp < 0) {
        perror("Socket");
        return 1;
    }


    memset(packet, 0, PACKET_SIZE); //tmp
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

        // Remplissage de l'en-tête IP
    ip->ihl = 5;  // Longueur de l'en-tête (5 * 4 = 20 octets)
    ip->version = 4;  // IPv4
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));  // Taille totale du paquet
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = INADDR_ANY;  // Adresse IP source
    ip->daddr = inet_addr("8.8.8.8");  // Adresse IP destination

    // Remplissage de l'en-tête TCP
    tcp->source = htons(12345);  // Port source
    tcp->dest = htons(443);  // Port destination
    tcp->seq = htonl(0);
    tcp->ack_seq = 0;
    tcp->doff = 5;  // Longueur de l'en-tête TCP (5 * 4 = 20 octets)
    tcp->syn = 1;  // Flag SYN
    tcp->window = htons(65535);
    tcp->check = 0;  // Le checksum sera calculé plus tard
    tcp->urg_ptr = 0;

    // Calcul du checksum IP
    ip->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

    // Informations sur la destination
    dest.sin_family = AF_INET;
    dest.sin_port = htons(443);
    dest.sin_addr.s_addr = inet_addr("8.8.8.8");

    // Permet d'inclure notre en-tête IP (sinon le noyau le remplace)
    int one = 1;
    if (setsockopt(sock_tcp, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        return 1;
    }

    // Envoi du paquet
    if (sendto(sock_tcp, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto");
        return 1;
    }
    printf("Paquet envoyé avec succès !\n");

    // whith other protocoll struct pollfd fds[3];
    struct pollfd fds[1];
    fds[0].fd = sock_tcp;
    fds[0].events = POLLIN;  // Écoute les paquets TCP reçus

    int ret = poll(fds, 1, 5000);

    if (ret < 0) {
        //have to handle error corectly
        printf("poll < 0");
        return -1;
    } else if (ret == 0) {
        printf("Timeout, aucun paquet reçu.\n");
    } else {
        struct sockaddr_in src_addr;
        socklen_t addr_len = sizeof(src_addr);
        char buffer[4096];
        if (fds[0].revents & POLLIN) {
            recvfrom(sock_tcp, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
            printf("Paquet TCP brut reçu de %s\n", inet_ntoa(src_addr.sin_addr));
        }
    }
    close(sock_tcp);
    return 0;
}

