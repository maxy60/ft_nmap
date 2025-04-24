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

void    analyse_no_reply(t_packet_list *packet_list, int packet_nbr) {
    int i = 0;
    while (i < packet_nbr) {
        i++;
    switch (packet_list[i].scan_type) {
            case SCAN_SYN:
                if (packet_list[i].active == 1)
                    packet_list[i].resp = is_filtered;
                break;
            case SCAN_ACK:
                if (packet_list[i].active == 1)
                    packet_list[i].resp = is_filtered;
                break;
            case SCAN_NULL:
                if (packet_list[i].active == 1)
                    packet_list[i].resp = is_open_filtered;
                break;
            case SCAN_FIN:
                if (packet_list[i].active == 1)
                    packet_list[i].resp = is_open_filtered;
                break;
            case SCAN_XMAS:
                if (packet_list[i].active == 1)
                    packet_list[i].resp = is_open_filtered;
                break;
            case SCAN_UDP:
                // construire resp UDP ici
                break;
        }
    }
}

/*void print_analyse(t_packet_list *packet_list, int packet_nbr, int scan_count) {
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
    }
}*/

#define LINE_WIDTH 80
#define CONCLUSION_COL_START 64  // Position approximative où commence "Conclusion"

void print_analyse(t_packet_list *packet_list, int packet_nbr, int scan_count) {
    printf("Port   Service Name         Results                                Conclusion\n");
    printf("-------------------------------------------------------------------------------\n");

    int i = 0;
    while (i < packet_nbr) {
        int port = packet_list[i].port;
        const char *service = packet_list[i].service_name ? packet_list[i].service_name : "Unassigned";

        printf("%-6d %-20s", port, service);

        int line_len = 26; // Already printed chars before results

        for (int j = 0; j < scan_count && i < packet_nbr; j++, i++) {
            char result[64];
            snprintf(result, sizeof(result), " %s(%s)",
                     scan_type_to_str(packet_list[i].scan_type),
                     port_state_to_str(packet_list[i].resp));

            int result_len = strlen(result);

            if (line_len + result_len >= CONCLUSION_COL_START) {
                printf("\n%-27s", "");  // indent to match Results column
                line_len = 27;
            }

            printf("%s", result);
            line_len += result_len;
        }

        // Align to the conclusion column (starting at col 64)
        int spaces_to_conclusion = CONCLUSION_COL_START - line_len;
        if (spaces_to_conclusion > 0)
            printf("%*s", spaces_to_conclusion, "");

        // Print the final conclusion based on last scan of the port (or pick a smarter logic)
        printf("%s\n", port_state_to_str(packet_list[i - 1].resp));
    }
}


