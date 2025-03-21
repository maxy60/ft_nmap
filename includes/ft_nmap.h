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

typedef struct  s_nmap
{
    struct sockaddr_in   dest;
    char    *dest_addr;
    int sockfd;
}   t_nmap;

// Union contenant les différents en-têtes de protocole
typedef union {
    struct tcphdr tcp;
    struct udphdr udp;
    struct icmphdr icmp;
} ProtocolHeader;

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Structure contenant l'en-tête IP et le protocole choisi
typedef struct s_packet{
    struct iphdr ip;         // En-tête IP
    ProtocolHeader protocol; // Union des protocoles
} t_packet;

uint16_t checksum(void *b, int len);
void    get_local_ip(char *ip);
void    packet_format(const char *ip, int port, char *packet);
void    analyse_packet(char *buffer);



#endif