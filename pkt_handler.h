#pragma once
#include <pcap.h>

/* Prototype of the Packet Handler */
void packet_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void frame_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void ether_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
void ip_handler(u_char* save_file, const u_char* pkt_data);
void arp_handler(u_char* save_file, const u_char* pkt_data);
void rarp_handler(u_char* save_file, const u_char* pkt_data);
void icmp_handler(u_char* save_file, const u_char* pkt_data);
void tcp_handler(u_char* save_file, const u_char* pkt_data);
void udp_handler(u_char* save_file, const u_char* pkt_data);
void data_handler(u_char* save_file, const u_char* pkt_data);
void dispatcher_handler(u_char*, const struct pcap_pkthdr*, const u_char*);