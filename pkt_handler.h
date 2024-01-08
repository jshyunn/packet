#pragma once
#include <pcap.h>

/* Prototype of the Packet Handler */
void packet_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void frame_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void ether_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void ip_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void arp_handler(const u_char* pkt_data);
void icmp_handler(const struct pcap_pkthdr* header, const u_char* pkt_data);
void tcp_handler(const struct pcap_pkthdr* header, const u_char* pkt_data);
void udp_handler(const struct pcap_pkthdr* header, const u_char* pkt_data);
void data_handler(const u_char* pkt_data);
char* convert_protocol(const u_char pro);