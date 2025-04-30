#include "ft_nmap.h"



static t_nmap g_nmap = {
	.sock_tcp = 0,
    .threads_num = 1,
    .port_start = 1,
    .port_end = 1024,
    .current_packet = 0,
    .packet_nbr = 0,
	.dest_addr = NULL,
	.dest = {
		.sin_family = AF_INET,
		.sin_port = 0
	}
};

int main(int ac, char **av) {
    srand(time(NULL));  // Initialisation de rand() avec le temps actuel
    if(ac == 1 || strcmp(av[1], "--help") == 0) {
        printf("ft_nmap [OPTIONS]\n --help     Print this help screen\n --ports    ports to scan (ex: 1-10 or 1,2,3 or 1,5-15)\n --ip       address to scan in dot format\n --file     File name containing IP addresses to scan,\n --speedup  [250 max] number of parallel threads to use\n --scan     SYN/NULL/FIN/XMAS/ACK/UDP\n");
        return 0;
    }
    int i = 0;
    int is_ip = 0;
    bool is_scan_spe = false;
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
        else if (strcmp(av[i], "--file") == 0 && i < ac) {
            printf("dans la condition\n");
            char *filename = av[i + 1];
            if(!check_file_access(filename)) {
                return 1;
            }
            g_nmap.ips = load_ips_from_file(filename, &g_nmap.total_ip);
            if (!g_nmap.ips) {
                    fprintf(stderr, "Erreur chargement des IPs\n"); //propre
                    exit(EXIT_FAILURE);
            }
            is_ip += 1;

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
        }
        else if (strcmp(av[i], "--scan") == 0 && i < ac) {
            if ((g_nmap.scan_count = parse_scan_types(av[i + 1], g_nmap.scan_types)) == -1)
                printf("err");
            is_scan_spe = true;
        }
        i++;
    }
    g_nmap.packet_nbr = ((g_nmap.port_end - g_nmap.port_start) * g_nmap.scan_count * g_nmap.total_ip);
    printf("threads num = %d, port_start = %d, port_end = %d\n",g_nmap.threads_num, g_nmap.port_start, g_nmap.port_end);
    if(is_ip == 1) { //just for use is_ip and compile easy
        printf("is_ip = %d\n", is_ip);
    }
    else {
        printf("prblm\n");
        return -1;
    }
    if (!is_scan_spe)
        g_nmap.scan_count = parse_scan_types("SYN,ACK,NULL,FIN,XMAS,UDP", g_nmap.scan_types);
        
    //initialize_capture(); no need furtivity
    //int sock_tcp;
    //int sock_udp;
    //int sock_icmp;
    //struct sockaddr_in dest;


    // Création du socket brut
    g_nmap.sock_tcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    //sock_udp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (g_nmap.sock_tcp < 0) {
        perror("Socket");
        return 1;
    }

    int one = 1;
    if (setsockopt(g_nmap.sock_tcp, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        return 1;
    }
    malloc_packet_list(&g_nmap);
    t_thread_info thread_info;
    thread_info.nmap = &g_nmap;
    pthread_t threads[g_nmap.threads_num];
    pthread_mutex_init(&thread_info.lock, NULL);
    pthread_mutex_init(&thread_info.list_lock, NULL);
      // Création du pool de threads
    for (int i = 0; i < g_nmap.threads_num; i++) {
        pthread_create(&threads[i], NULL, worker_thread, (void *)&thread_info);
    }
    // Attente de la fin des threads
    for (int i = 0; i < g_nmap.threads_num; i++) {
        pthread_join(threads[i], NULL);
    }
    struct pollfd fds[1];
    fds[0].fd = g_nmap.sock_tcp;
    fds[0].events = POLLIN;  // Écoute les paquets TCP reçus

    pthread_t timeout_thread;
    pthread_t pcap_thread;
    char errbuf[PCAP_ERRBUF_SIZE];
    thread_info.handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (!thread_info.handle) {
        fprintf(stderr, "Erreur ouverture pcap: %s\n", errbuf);
        return 1;
    }
    pthread_create(&timeout_thread, NULL, pcap_timeout_thread, (void *)&thread_info);
    pthread_create(&pcap_thread, NULL, pcap_listener_thread, (void *)&thread_info);

    pthread_join(timeout_thread, NULL);
    pthread_join(pcap_thread, NULL);
    pcap_close(thread_info.handle);
    pthread_mutex_destroy(&thread_info.lock);
    pthread_mutex_destroy(&thread_info.list_lock);
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
                uint8_t flags = tcp_resp->th_flags;
                printf("Paquet TCP brut reçu de %s au port: %d sur notre port: %d\n", inet_ntoa(src_addr.sin_addr), ntohs(tcp_resp->source), ntohs(tcp_resp->dest));
                mark_packet_received(ntohs(tcp_resp->source),(ntohs(tcp_resp->dest) -5000), flags, &thread_info);
            }
        }
    }
    analyse_no_reply(g_nmap.send_list, g_nmap.packet_nbr);
    for (int i = 0; i < g_nmap.packet_nbr; i++) {
        printf("Index %d: ip=%s ,port=%d, scan type: %u active=%d resp=%d\n", i,  g_nmap.send_list[i].ip, g_nmap.send_list[i].port, g_nmap.send_list[i].scan_type, g_nmap.send_list[i].active, g_nmap.send_list[i].resp);
    }
    print_analyse(g_nmap.send_list, g_nmap.packet_nbr, g_nmap.scan_count);
    free_ips(g_nmap.ips, g_nmap.total_ip);
    free(g_nmap.send_list);
    close(g_nmap.sock_tcp);

    return 0;
}

