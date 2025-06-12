#include <ft_nmap.h>

const char *scan_type_to_str(t_scan_type type)
{
  switch (type) {
    case SCAN_SYN:
      return "SYN";
    case SCAN_ACK:
      return "ACK";
    case SCAN_NULL:
      return "NULL";
    case SCAN_FIN:
      return "FIN";
    case SCAN_XMAS:
      return "XMAS";
    case SCAN_UDP:
      return "UDP";
    default:
      return "UNKNOWN";
  }
}

const char *port_state_to_str(t_port_state state)
{
  switch (state) {
    case is_filtered:
      return "Filtered";
    case is_open:
      return "Open";
    case is_closed:
      return "Closed";
    case is_unfiltered:
      return "Unfiltered";
    case is_open_filtered:
      return "Open|Filtered";
    case unknown:
      return "Unknown";
    default:
      return "???";
  }
}

void analyse_no_reply(t_packet_list *packet_list, int packet_nbr)
{
  int i = 0;
  while (i < packet_nbr) {
    i++;
    switch (packet_list[i].scan_type) {
      case SCAN_SYN:
        if (packet_list[i].active == 1) packet_list[i].resp = is_filtered;
        break;
      case SCAN_ACK:
        if (packet_list[i].active == 1) packet_list[i].resp = is_filtered;
        break;
      case SCAN_NULL:
        if (packet_list[i].active == 1) packet_list[i].resp = is_open_filtered;
        break;
      case SCAN_FIN:
        if (packet_list[i].active == 1) packet_list[i].resp = is_open_filtered;
        break;
      case SCAN_XMAS:
        if (packet_list[i].active == 1) packet_list[i].resp = is_open_filtered;
        break;
      case SCAN_UDP:
        // construire resp UDP ici
        break;
    }
  }
}

void print_analyse(t_packet_list *packet_list, int packet_nbr, int scan_count)
{
  printf(
      "IP:Port                 Service Name         Results                    "
      "            Conclusion\n");
  printf(
      "------------------------------------------------------------------------"
      "------------------------\n");

  int i = 0;
  while (i < packet_nbr) {
    int port = packet_list[i].port;
    const char *service = packet_list[i].service_name
                              ? packet_list[i].service_name
                              : "Unassigned";
    const char *ip = packet_list[i].ip;
    int port_width = 22 - strlen(ip);
    printf("%s:%-*d %-20s", ip, port_width, port, service);

    int line_len = 46;

    for (int j = 0; j < scan_count && i < packet_nbr; j++, i++) {
      char result[64];
      snprintf(result, sizeof(result), " %s(%s)",
               scan_type_to_str(packet_list[i].scan_type),
               port_state_to_str(packet_list[i].resp));

      int result_len = strlen(result);

      if (line_len + result_len >= 84) {
        printf("\n%-44s", "");
        line_len = 44;
      }

      printf("%s", result);
      line_len += result_len;
    }

    int spaces_to_conclusion = 84 - line_len;
    if (spaces_to_conclusion > 0) printf("%*s", spaces_to_conclusion, "");

    // revoir la conclusion
    printf("%s\n", port_state_to_str(packet_list[i - 1].resp));
  }
}
