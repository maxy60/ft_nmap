#include "ft_nmap.h"



static t_nmap g_nmap = {
	.sockfd = 0,
	.dest_addr = NULL,
	.dest = {
		.sin_family = AF_INET,
		.sin_port = 0
	}
};

//have to define if we need fct
//int parse_ip();

void    get_local_ip(char *ip) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) { // IPv4
            struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
            inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
            
            // Évite les IPs locales (loopback)
            if (strncmp(ip, "127.", 4) != 0) {
                freeifaddrs(ifaddr);
                return;
            }
        }
    }
    strcpy(ip, "Aucune IP trouvée");
    freeifaddrs(ifaddr);
}


/*void send_rst() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Option pour indiquer qu'on construit l'en-tête IP
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Création du paquet
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));
    packet_format("8.8.8.8", 443, packet);

    // Informations sur la destination
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(443);
    dest.sin_addr.s_addr = inet_addr("8.8.8.8");

    // Envoi du paquet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
    } else {
        printf("RST envoyé vers \n");
    }

    // Fermeture du socket après l'envoi
    close(sock);
}*/

int main(int ac, char **av) {
    srand(time(NULL));  // Initialisation de rand() avec le temps actuel
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

    //initialize_capture(); no need furtivity
    int sock_tcp;
    //int sock_udp;
    //int sock_icmp;
    //struct sockaddr_in dest;
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

    packet_format("8.8.8.8", 443, packet);
    g_nmap.dest.sin_family = AF_INET;
    g_nmap.dest.sin_port = htons(443);
    g_nmap.dest.sin_addr.s_addr = inet_addr("8.8.8.8");

    // Permet d'inclure notre en-tête IP (sinon le noyau le remplace)
    int one = 1;
    if (setsockopt(sock_tcp, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        return 1;
    }
    int received = 0;
    int j = 0;
    while (!received && j <= 3) {
        // Envoi du paquet
        if (sendto(sock_tcp, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&g_nmap.dest, sizeof(g_nmap.dest)) < 0) {
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
                analyse_packet(buffer);
                //send_rst();
                received = 1;
            }
        }
    }
    printf("RECEIVED = %d\n", received);
    close(sock_tcp);
    return 0;
}

