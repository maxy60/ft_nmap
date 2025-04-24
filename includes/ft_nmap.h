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
#include <stdbool.h>
#include <ctype.h>

//tmp
#define PACKET_SIZE 4096
#define MAX_SCAN_TYPES 6

typedef enum {
    SCAN_SYN,
    SCAN_ACK,
    SCAN_NULL,
    SCAN_FIN,
    SCAN_XMAS,
    SCAN_UDP
} t_scan_type;

typedef enum s_port_state {
    is_filtered,
    is_open,
    is_closed,
    is_unfiltered,
    is_open_filtered,
    unknown
} t_port_state;

typedef struct s_packet_list {
    int port;
    struct timeval sent_time; // Timestamp d'envoi
    char *service_name;
    int active;
    t_scan_type scan_type;
    t_port_state resp;

} t_packet_list;


typedef struct  s_nmap
{
    struct sockaddr_in   dest;
    char    *dest_addr;
    int sock_tcp;
    int threads_num;
    int port_start;
    int port_end;
    int current_packet;
    int packet_nbr;
    t_packet_list *send_list;
    t_scan_type scan_types[MAX_SCAN_TYPES];   // tableau dynamique
    int scan_count;            // nombre de scans à effectuer
}   t_nmap;

typedef struct s_thread_info {
    pthread_mutex_t lock;
    pthread_mutex_t list_lock;
    pcap_t          *handle;
    t_nmap          *nmap;
} t_thread_info;

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};


uint16_t checksum(void *b, int len);
void    get_local_ip(char *ip);
void    send_packet(const char *ip, int port, int socket, t_scan_type scan);
void    analyse_packet(char *buffer);
void    *worker_thread(void *arg);
t_packet_list *get_packet(int port, int scan, t_thread_info *thread_info);
void mark_packet_received(int port, int scan, uint8_t flags, t_thread_info *thread_info);
void handle_pcap_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void *pcap_listener_thread(void *arg);
void *pcap_timeout_thread(void *arg);
void    malloc_packet_list(t_nmap *nmap);
void    get_local_ip(char *ip);
int parse_port_range(const char *input, int *start, int *end);
int parse_scan_types(char *str, t_scan_type *scan_types);
void    print_analyse(t_packet_list *packet_list, int packet_nbr, int scan_count);
void    analyse_no_reply(t_packet_list *packet_list, int packet_nbr);

#endif