#include <stdio.h>
#include <string.h>

int main(int ac, char **av) {
    if(ac == 1 || strcmp(av[1], "--help") == 0) {
        printf("ft_nmap [OPTIONS]\n --help     Print this help screen\n --ports    ports to scan (ex: 1-10 or 1,2,3 or 1,5-15)\n --ip       address to scan in dot format\n --file     File name containing IP addresses to scan,\n --speedup  [250 max] number of parallel threads to use\n --scan     SYN/NULL/FIN/XMAS/ACK/UDP\n");
    }
    
}