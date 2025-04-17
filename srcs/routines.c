#include <ft_nmap.h>

void *worker_thread(void *arg) {
    t_thread_info *thread_info = (t_thread_info *)arg;
    t_nmap *nmap = thread_info->nmap;
    while (1) {
        pthread_mutex_lock(&thread_info->lock);
        if (nmap->current_packet == nmap->packet_nbr) {
            pthread_mutex_unlock(&thread_info->lock);
            break;  // On sort de la boucle car plus de ports
        }
        int packet_id = nmap->current_packet++;
        pthread_mutex_unlock(&thread_info->lock);
        int port_index = packet_id / nmap->scan_count;
        int scan_index = packet_id % nmap->scan_count;
        int port = nmap->port_start + port_index;
        pthread_mutex_lock(&thread_info->list_lock);
        nmap->send_list[packet_id].port = port;
        gettimeofday(&nmap->send_list[packet_id].sent_time, NULL);
        nmap->send_list[packet_id].active = 1;
        nmap->send_list[packet_id].scan_type = nmap->scan_types[scan_index];
        pthread_mutex_unlock(&thread_info->list_lock);
        send_packet(nmap->dest_addr, port, nmap->sock_tcp, nmap->scan_types[scan_index]);
        usleep(1000);  // Petite pause pour éviter la surcharge réseau
    }
    return NULL;
}

t_packet_list *get_packet(int port, t_thread_info *thread_info) {
    t_nmap *nmap = thread_info->nmap;
    for (int i = 0; i < nmap->packet_nbr; i++) {
        if (nmap->send_list[i].active && nmap->send_list[i].port == port) {
            return &nmap->send_list[i];
        }
    }
    return NULL;
}

void mark_packet_received(int port, t_thread_info *thread_info) {
    pthread_mutex_lock(&thread_info->list_lock);
    t_packet_list *packet = get_packet(port, thread_info);
    if (packet && packet->active == SCAN_SYN) {
        packet->active = 0;
        
        //packet->resp[SCAN_SYN].is_open = true;
        // ici interpreter le resultat 
    }
    else if (packet && packet->active) {          //etcc
            packet->active = 0;
    }
    pthread_mutex_unlock(&thread_info->list_lock);
}

void handle_pcap_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    t_thread_info *thread_info = (t_thread_info *)args;
    (void)header;
    const struct ip *ip_hdr = (struct ip *)(packet + 14); 
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    int ip_hdr_len = ip_hdr->ip_hl * 4;
    const struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);

    int src_port = ntohs(tcp_hdr->th_sport);
    mark_packet_received(src_port, thread_info); 

    printf("[PCAP] Reçu paquet TCP depuis port %d\n", src_port);
}

void *pcap_listener_thread(void *arg) {
    t_thread_info *thread_info = (t_thread_info *)arg;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(thread_info->handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(thread_info->handle, &fp) == -1) {
        fprintf(stderr, "Erreur filtre pcap\n");
        //pcap_close(handle);
        pthread_exit(NULL);
    }

    pcap_loop(thread_info->handle, -1, handle_pcap_packet, (u_char *)thread_info);
    return NULL;
}

void *pcap_timeout_thread(void *arg) {
    t_thread_info *thread_info = (t_thread_info *)arg;
    sleep(5); // ou usleep(), ou un chrono
    pcap_breakloop(thread_info->handle);
    return NULL;
}