#pragma once

#include "protocol.h"

/* Console */
void print_data(const frame*);
void print_frame_data(const frame_header*);
void print_ether_data(const ether_header*);
void print_ip_data(const ip_header*);
void print_arp_data(const arp*);
void print_icmp_data(const icmp_header*);
void print_tcp_data(const tcp_header*);
void print_udp_data(const udp_header*);
void print_l2_data(const frame*);
void print_l3_data(const ether*);
void print_l4_data(const ip*);

/* File */
void fprint_data(FILE*, const frame*);