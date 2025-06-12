#include "ft_nmap.h"

void *worker_thread(void *arg)
{
  t_thread_info *thread_info = (t_thread_info *)arg;
  t_nmap *nmap = thread_info->nmap;
  while (1) {
    pthread_mutex_lock(&thread_info->lock);
    if (nmap->current_packet == nmap->packet_nbr) {
      pthread_mutex_unlock(&thread_info->lock);
      break;
    }
    int packet_id = nmap->current_packet++;
    pthread_mutex_unlock(&thread_info->lock);
    int ip_index = packet_id /
                   ((nmap->port_end - nmap->port_start + 1) * nmap->scan_count);
    int remainder = packet_id % ((nmap->port_end - nmap->port_start + 1) *
                                 nmap->scan_count);
    int port_index = remainder / nmap->scan_count;  // recalculer
    int scan_index = remainder % nmap->scan_count;
    int port = nmap->port_start + port_index;
    pthread_mutex_lock(&thread_info->list_lock);
    nmap->send_list[packet_id].port = port;
    nmap->send_list[packet_id].active = 1;
    nmap->send_list[packet_id].scan_type = nmap->scan_types[scan_index];
    nmap->send_list[packet_id].ip = nmap->ips[ip_index];
    // un ip_index ensuite l'extraire du buffer pour l'envoyer à send_packet
    pthread_mutex_unlock(&thread_info->list_lock);
    send_packet(nmap->ips[ip_index], port, nmap->sock_tcp,
                nmap->scan_types[scan_index]);
    usleep(1000);  // Petite pause pour éviter la surcharge réseau
  }
  return NULL;
}

t_packet_list *get_packet(int port, int scan, char *ip,
                          t_thread_info *thread_info)
{
  t_nmap *nmap = thread_info->nmap;
  for (int i = 0; i < nmap->packet_nbr; i++) {
    if (nmap->send_list[i].active && nmap->send_list[i].port == port &&
        nmap->send_list[i].scan_type == (t_scan_type)scan &&
        strcmp(nmap->send_list[i].ip, ip) == 0) {
      return &nmap->send_list[i];
    }
  }
  return NULL;
}

void annalyse_resp(t_port_state *resp, t_scan_type scan_type, uint8_t flags)
{
  switch (scan_type) {
    case SCAN_SYN:
      if (flags == (TH_SYN | TH_ACK))
        *resp = is_open;
      else if (flags & TH_RST)
        *resp = is_closed;
      break;
    case SCAN_ACK:
      if (flags & TH_RST) *resp = is_unfiltered;
      break;
    case SCAN_NULL:
      if (flags & TH_RST) *resp = is_closed;
      break;
    case SCAN_FIN:
      if (flags & TH_RST) *resp = is_closed;
      break;
    case SCAN_XMAS:
      if (flags & TH_RST) *resp = is_closed;
      break;
    case SCAN_UDP:
      // construire resp UDP ici
      break;
  }
}

void mark_packet_received(t_packet_list *packet, uint8_t flags,
                          t_thread_info *thread_info)
{
  pthread_mutex_lock(&thread_info->list_lock);
  if (packet && packet->active == 1) {
    packet->active = 0;
    annalyse_resp(&packet->resp, packet->scan_type, flags);
  }
  pthread_mutex_unlock(&thread_info->list_lock);
}

void handle_pcap_packet(u_char *args, const struct pcap_pkthdr *header,
                        const u_char *packet)
{
  t_thread_info *thread_info = (t_thread_info *)args;
  (void)header;

  const struct ip *ip_hdr = (struct ip *)(packet + 14);
  int ip_hdr_len = ip_hdr->ip_hl * 4;

  if (ip_hdr->ip_p == IPPROTO_TCP) {
    const struct tcphdr *tcp_hdr =
        (struct tcphdr *)((u_char *)ip_hdr + ip_hdr_len);

    int src_port = ntohs(tcp_hdr->th_sport);
    int scan = ntohs(tcp_hdr->th_dport) - 5000;
    uint8_t flags = tcp_hdr->th_flags;
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    t_packet_list *my_packet = get_packet(src_port, scan, src_ip, thread_info);

    mark_packet_received(my_packet, flags, thread_info);

    printf(
        "[PCAP] TCP packet received from port %d for scan %d, th_flags: %d\n",
        src_port, scan, tcp_hdr->th_flags);

  } else if (ip_hdr->ip_p == IPPROTO_UDP) {
    const struct udphdr *udp_hdr =
        (struct udphdr *)((u_char *)ip_hdr + ip_hdr_len);

    int src_port = ntohs(udp_hdr->uh_sport);
    int scan = ntohs(udp_hdr->uh_dport) - 5000;

    // les paquets udp n'ont pas de flag
    // mark_packet_received(src_port, scan, 0, thread_info);

    printf("[PCAP] UDP packet received from port %d for scan %d\n", src_port,
           scan);
  }
}

void *pcap_listener_thread(void *arg)
{
  t_thread_info *thread_info = (t_thread_info *)arg;
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  if (pcap_compile(thread_info->handle, &fp, filter_exp, 0,
                   PCAP_NETMASK_UNKNOWN) == -1 ||
      pcap_setfilter(thread_info->handle, &fp) == -1) {
    fprintf(stderr, "Erreur filtre pcap\n");
    // pcap_close(handle);
    pthread_exit(NULL);
  }

  pcap_loop(thread_info->handle, -1, handle_pcap_packet, (u_char *)thread_info);
  return NULL;
}

void *pcap_timeout_thread(void *arg)
{
  t_thread_info *thread_info = (t_thread_info *)arg;
  sleep(5);  // ou usleep()
  pcap_breakloop(thread_info->handle);
  return NULL;
}
