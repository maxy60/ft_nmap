#include <ft_nmap.h>


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    (void)header;
    (void)packet;
    printf("Paquet intercepté ! Taille : %d octets\n", header->len);
}

void    *loop_capture(void *arg) {
    pcap_t  *handle = (pcap_t *)arg;
    printf("loop is starting\n");

    pcap_loop(handle, -1, packet_handler, NULL);
    return NULL;
}

void initialize_capture() { // to catch kernel packet
    pcap_if_t *alldevs, *dev;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];


   // Récupérer toutes les interfaces disponibles
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Erreur pcap_findalldevs: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Prendre la première interface disponible
    dev = alldevs;
    if (dev == NULL) {
        fprintf(stderr, "Aucune interface réseau disponible\n");
        exit(EXIT_FAILURE);
    }

    printf("Interface détectée : %s\n", dev->name);
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Erreur pcap: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    struct bpf_program filter;
    char filter_exp[] = "tcp and src host 10.0.2.15 and (tcp[tcpflags] & tcp-rst != 0 or tcp[tcpflags] & tcp-ack != 0)";

    // Compile le filtre
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Erreur filtre BPF: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Applique le filtre
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Erreur application filtre: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, loop_capture, (void *)handle) != 0) {
        fprintf(stderr, "Erreur création thread\n");
        exit(EXIT_FAILURE);
    }

    printf("capture en arrière plan lancé\n");
}