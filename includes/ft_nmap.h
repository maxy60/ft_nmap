#ifndef FT_NMAP_H
# define FT_NMAP_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <pthread.h>
#include <ifaddrs.h>

//tmp
#define PACKET_SIZE 4096

typedef struct s_packet_list {
    int port;
    struct timeval sent_time; // Timestamp d'envoi
    int active;
    int resp;
} t_packet_list;

typedef struct s_scan_result {
    int port;
    int state;     // OPEN, CLOSED, FILTERED, etc.
    char reason[64]; // TCP RST reçu, aucune réponse, etc.
} t_scan_result;

enum scan_type {
    SCAN_SYN,
    SCAN_ACK,
    SCAN_NULL,
    SCAN_FIN,
    SCAN_XMAS,
    UDP
};

typedef struct  s_nmap
{
    struct sockaddr_in   dest;
    char    *dest_addr;
    int sock_tcp;
    int threads_num;
    int port_start;
    int port_end;
    int current_port;
    int packet_nbr;
    t_packet_list *send_list;
}   t_nmap;


struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Union contenant les différents en-têtes de protocole
typedef union {
    struct tcphdr tcp;
    struct udphdr udp;
    struct icmphdr icmp;
} ProtocolHeader;

// Structure contenant l'en-tête IP et le protocole choisi
typedef struct s_packet {
    struct iphdr ip;         // En-tête IP
    ProtocolHeader protocol; // Union des protocoles
} t_packet;


uint16_t checksum(void *b, int len);
void    get_local_ip(char *ip);
void    send_packet(const char *ip, int port, int socket);
void    analyse_packet(char *buffer);



#endif