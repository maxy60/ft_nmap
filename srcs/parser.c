#include <ft_nmap.h>

int parse_arg(int ac, char **av, t_nmap *nmap)
{
  if (ac == 1 || strcmp(av[1], "--help") == 0) {
    printf(
        "ft_nmap [OPTIONS]\n --help     Print this help screen\n --ports    "
        "ports to scan (ex: 1-10 or 1,2,3 or 1,5-15)\n --ip       address to "
        "scan in dot format\n --file     File name containing IP addresses to "
        "scan,\n --speedup  [250 max] number of parallel threads to use\n "
        "--scan     SYN/NULL/FIN/XMAS/ACK/UDP\n");
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
        printf("PRBLM\n");
        return 1;  // gerer l'erreur correctement
      }
      struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
      nmap->ips = malloc(sizeof(char *));
      char *ip_tmp = inet_ntoa(addr->sin_addr);
      nmap->ips[0] = strdup(ip_tmp);
      nmap->total_ip = 1;
      is_ip += 1;
    } else if (strcmp(av[i], "--file") == 0 && i < ac) {
      char *filename = av[i + 1];
      if (!check_file_access(filename)) {
        return 1;
      }
      nmap->ips = load_ips_from_file(filename, &nmap->total_ip);
      if (!nmap->ips) {
        fprintf(stderr, "Erreur chargement des IPs\n");  // propre
        exit(EXIT_FAILURE);
      }
      is_ip += 1;

    } else if (strcmp(av[i], "--speedup") == 0 && i < ac) {
      nmap->threads_num = atoi(av[i + 1]);
      if (nmap->threads_num < 0 || nmap->threads_num > 250) {
        printf("number of threads need to be in this range: [1-250]\n");
        return 1;
      }
    } else if (strcmp(av[i], "--port") == 0 && i < ac) {
      if (parse_port_range(av[i + 1], &nmap->port_start, &nmap->port_end) !=
          0) {
        printf("incorrect port range\n");
        return 1;
      }
    } else if (strcmp(av[i], "--scan") == 0 && i < ac) {
      if ((nmap->scan_count = parse_scan_types(av[i + 1], nmap->scan_types)) ==
          -1) {
        return 1;
      }
      is_scan_spe = true;
    }
    i++;
  }
  if (!is_ip) return 1;

  if (is_scan_spe != true) {
    char *str = strdup("SYN,ACK,NULL,FIN,XMAS,UDP");
    if ((nmap->scan_count = parse_scan_types(str, nmap->scan_types)) == -1)
      return 1;
    free(str);
  }
  return 0;
}
