#include <ft_nmap.h>

void malloc_packet_list(t_nmap *nmap) {
    int range;

    if (nmap->port_end == nmap->port_start) {
        range = 1 * nmap->scan_count;
    }

    range = nmap->packet_nbr;
    printf("range: %d\n", range);
    nmap->send_list = malloc(sizeof(t_packet_list) * range);
    if (!nmap->send_list) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(nmap->send_list, 0, sizeof(t_packet_list) * range);
}



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

int parse_port_range(const char *input, int *start, int *end) {
    char *dash = strchr(input, '-');
    if (!dash) {
        *start = atoi(input);
        *end = atoi(input);
        if (*start < 0 || *start > 65535)
            return -1;
        return 0;
    }

    *dash = '\0';
    
    *start = atoi(input);
    *end = atoi(dash + 1);

    if (*start < 0 || *start > 65535 || *end < 0 || *end > 65535 || *start > *end) {
        return -1;
    }
    return 0;
}

int parse_scan_types(char *str, t_scan_type *scan_types) {
    int count = 0;
    char *token = strtok(str, ",");

    while (token != NULL) {
        for (char *p = token; *p; ++p)
            *p = toupper((unsigned char)*p);

        t_scan_type parsed;
        if (strcmp(token, "SYN") == 0)
            parsed = SCAN_SYN;
        else if (strcmp(token, "ACK") == 0)
            parsed = SCAN_ACK;
        else if (strcmp(token, "NULL") == 0)
            parsed = SCAN_NULL;
        else if (strcmp(token, "FIN") == 0)
            parsed = SCAN_FIN;
        else if (strcmp(token, "XMAS") == 0)
            parsed = SCAN_XMAS;
        else if (strcmp(token, "UDP") == 0)
            parsed = SCAN_UDP;
        else {
            fprintf(stderr, "Type de scan inconnu : %s\n", token);
            return -1;
        }

        // Vérif doublon dans le tableau existant
        for (int i = 0; i < count; ++i) {
            if (scan_types[i] == parsed) {
                fprintf(stderr, "Erreur : scan \"%s\" spécifié en double\n", token);
                return -1;
            }
        }

        if (count >= MAX_SCAN_TYPES) {
            fprintf(stderr, "Trop de types de scans (max %d)\n", MAX_SCAN_TYPES);
            return -1;
        }

        scan_types[count++] = parsed;
        token = strtok(NULL, ",");
    }

    return count;
}