#include "ft_nmap.h"

static t_nmap g_nmap = {
    .sock_tcp = 0,
    .threads_num = 1,
    .port_start = 1,
    .port_end = 1024,
    .current_packet = 0,
    .packet_nbr = 0,
};

int main(int ac, char **av)
{
  srand(time(NULL));  // Initialisation de rand() avec le temps actuel
  if (parse_arg(ac, av, &g_nmap) == 1) {
    printf("je suis ici\n");
    return 2;
  }
  g_nmap.port_end += 1;
  g_nmap.packet_nbr = ((g_nmap.port_end - g_nmap.port_start) *
                       g_nmap.scan_count * g_nmap.total_ip);
  printf("%d = (%d - %d) * %d * %d\n", g_nmap.packet_nbr, g_nmap.port_end,
         g_nmap.port_start, g_nmap.scan_count, g_nmap.total_ip);

  // initialize_capture(); no need furtivity
  // int sock_tcp;
  // int sock_udp;
  // int sock_icmp;
  // struct sockaddr_in dest;

  // Création du socket brut
  g_nmap.sock_tcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  // sock_udp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
  if (g_nmap.sock_tcp < 0) {
    perror("Socket");
    return 1;
  }

  int one = 1;
  if (setsockopt(g_nmap.sock_tcp, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) <
      0) {
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
  pthread_create(&timeout_thread, NULL, pcap_timeout_thread,
                 (void *)&thread_info);
  pthread_create(&pcap_thread, NULL, pcap_listener_thread,
                 (void *)&thread_info);

  pthread_join(timeout_thread, NULL);
  pthread_join(pcap_thread, NULL);
  pcap_close(thread_info.handle);
  pthread_mutex_destroy(&thread_info.lock);
  pthread_mutex_destroy(&thread_info.list_lock);
  while (1) {
    int ret = poll(fds, 1, 5000);
    if (ret < 0) {
      // have to handle error corectly
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
        recvfrom(g_nmap.sock_tcp, buffer, sizeof(buffer), 0,
                 (struct sockaddr *)&src_addr, &addr_len);
        struct iphdr *ip_resp = (struct iphdr *)buffer;
        struct tcphdr *tcp_resp =
            (struct tcphdr *)(buffer + (ip_resp->ihl * 4));
        uint8_t flags = tcp_resp->th_flags;
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_resp->saddr), src_ip, INET_ADDRSTRLEN);
        t_packet_list *my_packet =
            get_packet(ntohs(tcp_resp->source), (ntohs(tcp_resp->dest) - 5000),
                       src_ip, &thread_info);  // ici rajouter l'ip

        printf("Paquet TCP brut reçu de %s au port: %d sur notre port: %d\n",
               inet_ntoa(src_addr.sin_addr), ntohs(tcp_resp->source),
               ntohs(tcp_resp->dest));
        mark_packet_received(my_packet, flags, &thread_info);
      }
    }
  }
  analyse_no_reply(g_nmap.send_list, g_nmap.packet_nbr);
  for (int i = 0; i < g_nmap.packet_nbr; i++) {
    printf("Index %d: ip=%s ,port=%d, scan type: %u active=%d resp=%d\n", i,
           g_nmap.send_list[i].ip, g_nmap.send_list[i].port,
           g_nmap.send_list[i].scan_type, g_nmap.send_list[i].active,
           g_nmap.send_list[i].resp);
  }
  print_analyse(g_nmap.send_list, g_nmap.packet_nbr, g_nmap.scan_count);
  free_ips(g_nmap.ips, g_nmap.total_ip);
  free(g_nmap.send_list);
  close(g_nmap.sock_tcp);

  return 0;
}
