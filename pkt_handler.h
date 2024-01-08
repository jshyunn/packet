#pragma once
#include <pcap.h>
#include "protocol.h"

/* Prototype of the Packet Handler */
void packet_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data);
frame frame_handler(const struct pcap_pkthdr* header, const u_char* pkt_data);
ether ether_handler(const u_char* pkt_data);
ip ip_handler(const u_char* pkt_data);
arp arp_handler(const u_char* pkt_data);
icmp icmp_handler(const u_char* pkt_data);
tcp tcp_handler(const u_char* pkt_data);
udp udp_handler(const u_char* pkt_data);