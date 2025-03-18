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

//tmp
#define PACKET_SIZE 4096

typedef struct  s_nmap
{
    struct sockaddr_in   dest;
    char    *dest_addr;
    int sockfd;
}   t_nmap;


#endif