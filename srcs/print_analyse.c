#include <ft_nmap.h>

const char *scan_type_to_str(t_scan_type type) {
    switch (type) {
        case SCAN_SYN: return "SYN";
        case SCAN_ACK: return "ACK";
        case SCAN_NULL: return "NULL";
        case SCAN_FIN: return "FIN";
        case SCAN_XMAS: return "XMAS";
        case SCAN_UDP: return "UDP";
        default: return "UNKNOWN";
    }
}

const char *port_state_to_str(t_port_state state) {
    switch (state) {
        case is_filtered: return "Filtered";
        case is_open: return "Open";
        case is_closed: return "Closed";
        case is_unfiltered: return "Unfiltered";
        case is_open_filtered: return "Open|Filtered";
        case unknown: return "Unknown";
        default: return "???";
    }
}


void print_analyse(t_packet_list *packet_list, int packet_nbr, int scan_count) {
    printf("Port   Service Name         Results                                Conclusion\n");
    printf("-------------------------------------------------------------------------------\n");

    int i = 0;
    while (i < packet_nbr) {
        printf("%-6d %-20s", packet_list[i].port, packet_list[i].service_name ? packet_list[i].service_name : "Unassigned");

        for (int j = 0; j < scan_count; j++) {
                printf(" %s(%s)", scan_type_to_str(packet_list[i].scan_type), port_state_to_str(packet_list[i].resp));
            i++;
        }
        printf("\n%-27s%u\n", "", packet_list[i].resp);
        printf("packet_nbr: %d, i = %d\n", packet_nbr, i);
    }
}
