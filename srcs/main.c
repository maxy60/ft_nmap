#include "ft_nmap.h"



static t_nmap g_nmap = {
	.sock_tcp = 0,
    .threads_num = 1,
    .port_start = 1,
    .port_end = 1024,
    .current_port = 1,
    .packet_nbr = 0,
	.dest_addr = NULL,
	.dest = {
		.sin_family = AF_INET,
		.sin_port = 0
	}
};

void    malloc_packet_list() {
    int range = g_nmap.port_end - g_nmap.port_start + 1;
    g_nmap.packet_nbr = range;
    printf("ICI LA RANGE: %d\n", range);

    g_nmap.send_list = malloc(sizeof(t_packet_list) * range);
    if (!g_nmap.send_list) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(g_nmap.send_list, 0, sizeof(t_packet_list) * range);
}

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

int parse_port_range(const char *input, int *start, int *end) {
    char *dash = strchr(input, '-');
    if (!dash) {
        return -1;  
    }

    *dash = '\0';  // Séparation des deux nombres (attention : modifie la chaîne)
    
    *start = atoi(input);   // Convertit la première partie en entier
    *end = atoi(dash + 1);  // Convertit la deuxième partie en entier

    if (*start < 0 || *start > 65535 || *end < 0 || *end > 65535 || *start > *end) {
        return -1;  // Plage invalide
    }
    g_nmap.current_port = atoi(input); // beurk
    return 0;
}

pthread_mutex_t lock;
pthread_mutex_t list_lock;

void *worker_thread(void *arg) {
    (void)arg;
    while (g_nmap.current_port != g_nmap.port_end +1) {
        int index = g_nmap.current_port - g_nmap.port_start;
        pthread_mutex_lock(&lock);
        int port = g_nmap.current_port++;
        pthread_mutex_unlock(&lock);

        //pthread_mutex_lock(&list_lock);
        g_nmap.send_list[index].port = port;
        gettimeofday(&g_nmap.send_list[index].sent_time, NULL);
        g_nmap.send_list[index].active = 1;
        //pthread_mutex_unlock(&list_lock);
        send_packet(g_nmap.dest_addr, port, g_nmap.sock_tcp);
        usleep(1000);  // Petite pause pour éviter la surcharge réseau
    }
    return NULL;
}

t_packet_list *get_packet(int port) {
    for (int i = 0; i < g_nmap.packet_nbr; i++) {
        if (g_nmap.send_list[i].active && g_nmap.send_list[i].port == port) {
            return &g_nmap.send_list[i];
        }
    }
    return NULL;
}

void mark_packet_received(int port) {
    pthread_mutex_lock(&list_lock);
    t_packet_list *packet = get_packet(port);
    if (packet && packet->active) {
        packet->active = 0;
        packet->resp = 1;
        // ici interpreter le resultat 
    }
    pthread_mutex_unlock(&list_lock);
}

void handle_pcap_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Skip Ethernet header
    (void)args;
    (void)header;
    const struct ip *ip_hdr = (struct ip *)(packet + 14); // 14 = taille eth header
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);

    int src_port = ntohs(tcp_hdr->th_sport);
    //int dst_port = ntohs(tcp_hdr->th_dport);

    // 🔒 Mutex sur la liste partagée (packet_list)
    // Ici tu marques le port comme reçu si tu le reconnais dans ta liste d’envois
    mark_packet_received(src_port);  // à toi de l'implémenter proprement

    printf("[PCAP] Reçu paquet TCP depuis port %d\n", src_port);
}

void *pcap_listener_thread(void *arg) {
    pcap_t *handle = (pcap_t *)arg;
    //(void)arg;
    //char errbuf[PCAP_ERRBUF_SIZE];
    //pcap_t *handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); // il faut un choix d'interface réseau dynamique
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Erreur filtre pcap\n");
        //pcap_close(handle);
        pthread_exit(NULL);
    }

    pcap_loop(handle, -1, handle_pcap_packet, NULL);
    return NULL;
}

void *pcap_timeout_thread(void *arg) {
    sleep(5); // ou usleep(), ou un chrono
    pcap_breakloop((pcap_t *)arg);
    return NULL;
}



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
            if (getaddrinfo(av[i + 1], NULL, &hints, &res)) {
                return 1;   //gerer l'erreur correctement
            }
            struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
            g_nmap.dest_addr = inet_ntoa(addr->sin_addr);
            g_nmap.dest.sin_addr.s_addr = addr->sin_addr.s_addr;
            is_ip += 1;
            printf("des_addr = %s\n", g_nmap.dest_addr);
        }
        else if (strcmp(av[i], "--speedup") == 0 && i < ac) {
            g_nmap.threads_num = atoi(av[i + 1]);
            if (g_nmap.threads_num < 1 || g_nmap.threads_num > 250) {
                printf("number of threads need to be in this range: [1-250]\n");
                return 1;
            }
        }
        else if (strcmp(av[i], "--port") == 0 && i < ac) {
            if (parse_port_range(av[i + 1], &g_nmap.port_start, &g_nmap.port_end) != 0) {
                printf("incorrect port range\n");
                return -1;
            }
            g_nmap.packet_nbr = g_nmap.port_end - g_nmap.port_start;
        }
        i++;
    }

    printf("threads num = %d, port_start = %d, port_end = %d\n",g_nmap.threads_num, g_nmap.port_start, g_nmap.port_end);
    if(is_ip == 1) { //just for use is_ip and compile easy
        printf("is_ip = %d\n", is_ip);
    }
    else {
        printf("prblm\n");
        return -1;
    }

    //initialize_capture(); no need furtivity
    //int sock_tcp;
    //int sock_udp;
    //int sock_icmp;
    //struct sockaddr_in dest;


    // Création du socket brut
    g_nmap.sock_tcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    //sock_udp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    //sock_icmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (g_nmap.sock_tcp < 0) {
        perror("Socket");
        return 1;
    }

    int one = 1;
    if (setsockopt(g_nmap.sock_tcp, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        return 1;
    }

    malloc_packet_list(); // malloc la liste ou stocker tout les paquets envoyé
    pthread_t threads[g_nmap.threads_num];
    pthread_mutex_init(&lock, NULL);
    pthread_mutex_init(&list_lock, NULL);

      // Création du pool de threads
    for (int i = 0; i < g_nmap.threads_num; i++) {
        pthread_create(&threads[i], NULL, worker_thread, NULL);
    }

    // Attente de la fin des threads
    for (int i = 0; i < g_nmap.threads_num; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&lock);
    pthread_mutex_destroy(&list_lock);

    // whith other protocoll struct pollfd fds[3];
    struct pollfd fds[1];
    fds[0].fd = g_nmap.sock_tcp;
    fds[0].events = POLLIN;  // Écoute les paquets TCP reçus

    pthread_t timeout_thread;
    pthread_t pcap_thread;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Erreur ouverture pcap: %s\n", errbuf);
        return 1;
    }
    pthread_create(&timeout_thread, NULL, pcap_timeout_thread, handle);
    pthread_create(&pcap_thread, NULL, pcap_listener_thread, handle);

    pthread_join(timeout_thread, NULL);
    pthread_join(pcap_thread, NULL);
    pcap_close(handle);
    while (1) {   
        int ret = poll(fds, 1, 5000);
        if (ret < 0) {
            //have to handle error corectly
            printf("poll < 0");
            return -1;
        } else if (ret == 0) {
            printf("Timeout, aucun paquet reçu.\n");
            break;
        } else {
            struct sockaddr_in src_addr;
            socklen_t addr_len = sizeof(src_addr);
            char buffer[4096];
            if (fds[0].revents & POLLIN) {
                recvfrom(g_nmap.sock_tcp, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
                struct iphdr *ip_resp = (struct iphdr *)buffer;
                struct tcphdr *tcp_resp = (struct tcphdr *)(buffer + (ip_resp->ihl * 4));
                printf("Paquet TCP brut reçu de %s au port: %d\n", inet_ntoa(src_addr.sin_addr), ntohs(tcp_resp->source));
                mark_packet_received(ntohs(tcp_resp->source));
                //analyse_packet(buffer);
            }
        }
    }
    for (int i = 0; i < g_nmap.packet_nbr; i++) {
        printf("Index %d: port=%d, active=%d\n", i, g_nmap.send_list[i].port, g_nmap.send_list[i].active);
    }
    free(g_nmap.send_list);    
    close(g_nmap.sock_tcp);

    return 0;
}

