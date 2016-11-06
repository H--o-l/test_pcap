/* Enoncé :
++++++++++++++++++++++++++++++++++++++++
Écrire un programme en C ou C++:

Entrée : 1 fichier pcap
Sortie : Sur la sortie standard affiche, par tranche de 10 secondes,
la somme de la taille des packets envoyée par IP et en ordre décroissant.

Contraintes : bibliothèques standard du langage + libpcap si besoin.

Exemple de sortie :

    0
    --------------------

    1363341600
    --------------------
    5012992 1.1.1.74
    4203451 1.2.0.2
    15 1.1.80.0
    8 1.2.1.28
    8 2.134.1.28
    1 0.0.0.0

    1363341610
    --------------------
    7367984 1.8.0.2
    5882592 6.0.15.14
    5382677 1.4.34.57
    1364992 1.6.1.74
    960832 6.0.10.84
    1 0.0.0.0

++++++++++++++++++++++++++++++++++++++++

Solution based on https://www.rhyous.com/2011/11/13/how-to-read-a-pcap-file-from-wireshark-with-c/
And http://homes.di.unimi.it/~gfp/SiRe/2002-03/progetti/libpcap-tutorial.html

Asumption:
All packet are IPV4
*/

/* --------------------------------- Libs --------------------------------- */
#include <iostream>
#include <map>
#include <vector>
#include <algorithm> 
#include <pcap.h>
using namespace std; // shortcut

/* --------------------------------- Defines --------------------------------- */
#define _BSD_SOURCE 1 
#define	ETHER_ADDR_LEN		6 
 
/* --------------------------------- Structures --------------------------------- */
/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* Internet address. */
struct in_addr {
    u_int       s_addr;     /* address in network byte order */
};

/* IP header */
struct sniff_ip {
    #if BYTE_ORDER == LITTLE_ENDIAN
    u_int ip_hl:4, /* header length */
    ip_v:4; /* version */
    #if BYTE_ORDER == BIG_ENDIAN
    u_int ip_v:4, /* version */
    ip_hl:4; /* header length */
    #endif
    #endif /* not _IP_VHL */
    u_char ip_tos; /* type of service */
    u_short ip_len; /* total length */
    u_short ip_id; /* identification */
    u_short ip_off; /* fragment offset field */
    #define IP_RF 0x8000 /* reserved fragment flag */
    #define IP_DF 0x4000 /* dont fragment flag */
    #define IP_MF 0x2000 /* more fragments flag */
    #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
    u_char ip_ttl; /* time to live */
    u_char ip_p; /* protocol */
    u_short ip_sum; /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

/* --------------------------------- Funtion inet_ntoa --------------------------------- */
static char buffer[18];
char *inet_ntoa (u_int in){
    unsigned char *bytes = (unsigned char *) &in;
    snprintf (buffer, sizeof (buffer), "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return buffer;
}

/* --------------------------------- Funtions --------------------------------- */
int main(int argc, char *argv[])
{
    // pcap handling
    char errbuff[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    const u_char *data;
    
    // Open file
    string file;
    if(argv[1] != NULL && (file = argv[1]) != "") {cout << "Used pcap file: " << file << endl;} else {cout << "No input file" << endl; return 0;}
    pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);
    
    // Loop input
    map <u_long, map<u_int, u_int> > time_map;
    while (pcap_next_ex(pcap, &header, &data) >= 0)
    { 
        // Show Epoch Time
        u_long    packet_time = ((u_long) header->ts.tv_sec / 10)*10;
        u_int     packet_ip   = (((struct sniff_ip*)(data + sizeof(struct sniff_ethernet)))->ip_src.s_addr);
        u_int     packet_len  = header->len;

        if(time_map.find(packet_time) == time_map.end()){
            cout << packet_time << " " << packet_len << " " << packet_ip << endl;
            time_map[packet_time][packet_ip] = packet_len;
        }
        break;
    }
    
    // loop result
    for (map<u_long, map<u_int, u_int> >::iterator iterator_time_map = time_map.begin(); iterator_time_map != time_map.end(); iterator_time_map++)
    {
        cout << endl << iterator_time_map->first << endl;
        cout << "--------------------" << endl;
        
        // sort packet by size
        vector<pair<int, u_int> > com_by_size;
        for (map<u_int, u_int>::iterator iterator_ip_map = iterator_time_map->second.begin(); iterator_ip_map != iterator_time_map->second.end(); ++iterator_ip_map){
            com_by_size.push_back(make_pair(iterator_ip_map->second, iterator_ip_map->first));
        }
        sort(com_by_size.begin(), com_by_size.end());    
        
        // print packet
        for(vector<pair<int, u_int> >::iterator vector_iterator = com_by_size.begin(); vector_iterator != com_by_size.end(); vector_iterator++){
            cout << vector_iterator->first << " " << inet_ntoa(vector_iterator->second) << endl;
        }
    }
}
