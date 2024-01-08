#pragma once
#include <pcap.h>

/* IP Addresss Structure */
typedef struct _ip_addr ip_addr;
struct _ip_addr {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};


/* MAC Addresss Structure */
typedef struct _mac_addr mac_addr;
struct _mac_addr {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
};


/* ICMP Header Structure */
typedef struct _icmp_header icmp_header;
struct _icmp_header {
	u_char type; /* Type */
	u_char code; /* Code */
	u_short checksum; /* Checksum */
	u_short id; /* Identifier */
	u_short seq_num; /* Sequence number */
};

/* TYPE Field */
typedef enum _icmp_body_type icmp_body_type;
enum _icmp_body_type {
	ICMP_ECHO_REP = 0, /* Echo reply */
	ICMP_ECHO_REQ = 8 /* Echo request */
};

/* ICMP Structure*/
typedef struct _icmp icmp;
struct _icmp {
	icmp_header header;
	u_char* body;
};


/* TCP Header Structure */
typedef struct _tcp_header tcp_header;
struct _tcp_header {
	u_short sport; /* Source port */
	u_short dport; /* Destination port */
	u_int seq_num; /* Sequence number */
	u_int ack_num; /* Acknowledgement number */
	u_short hlen_flags; /* Header length(4bits) & Flags(12bits) */
	u_short win_size; /* Window size */
	u_short checksum; /* Checksum */
	u_short urgent_ptr; /* Urgent Pointer*/
};

/* Port Field */
typedef enum _tcp_port_type tcp_port_type;
enum _tcp_port_type {
	FTP = 20,
	SSH = 22,
	TELNET = 23,
	SMTP = 25,
	HTTP = 80,
	POP3 = 110,
	IMAP4 = 143,
	HTTPS = 443
};

/* TCP Structure */
typedef struct _tcp tcp;
struct _tcp {
	tcp_header header;
	u_char* body;
};


/* UDP Header Structure */
typedef struct _udp_header udp_header;
struct _udp_header {
	u_short sport; /* Source port */
	u_short dport; /* Destination port */
	u_short tlen; /* Total length*/
	u_short checksum; /* Checksum */
};

/* UDP Structure */
typedef struct _udp udp;
struct _udp {
	udp_header header;
	u_char* body;
};


/* ARP Structure */
typedef struct _arp arp;
struct _arp {
	u_short hard; /*Hardware type */
	u_short pro; /* Protocol type */
	u_char hlen; /* Hardware address length */
	u_char plen; /* Protocol address length */
	u_short op; /* Opcode */
	mac_addr sha; /* Source hardware address(mac address) */
	ip_addr spa; /* Source protocol address(ip address) */
	mac_addr dha; /* Destination hardware address(mac address) */
	ip_addr dpa; /* Destination protocol address(ip address) */
};


/* IP Header Structure */
typedef struct _ip_header ip_header;
struct _ip_header {
	u_char ver_ihl; /* Version(4bits) & Internet header length(4bits) */
	u_char tos; /* Type of service */
	u_short tlen; /* Total length */
	u_short id; /* Identification */
	u_short off; /* Flags(3bits) & Fargment offset(13bits) */
	u_char ttl; /* Time to live */
	u_char pro; /* Protocol */
	u_short checksum; /* Header Checksum */
	ip_addr src; /* Source address */
	ip_addr dst; /* Destination address */
};

/* IP Body Structure */
typedef struct _ip_body ip_body;
struct _ip_body {
	icmp icmp_data;
	tcp tcp_data;
	udp udp_data;
};

/* Type Field */
typedef enum _ip_type ip_body_type;
enum _ip_type {
	ICMP = 0x0001,
	IGMP = 0x0002,
	TCP = 0x0006,
	UDP = 0x0011
};

/* IP Structure */
typedef struct _ip ip;
struct _ip {
	ip_header header;
	ip_body body;
};


/* Ethernet Header Structure */
typedef struct _ether_header ether_header;
struct _ether_header {
	mac_addr dst; /* Destination MAC address */
	mac_addr src; /* Source MAC address */
	u_short type; /* Type(1byte) & Length(1byte) */
};

/* Ethernet Body Structure */
typedef struct _ether_body ether_body;
struct _ether_body {
	ip ip_data;
	arp arp_data;
};

/* Type Field */
typedef enum _ether_body_type ether_body_type;
enum _ether_body_type {
	IP = 0x0800,
	ARP = 0x0806
};

/* Ethernet Structure */
typedef struct _ether ether;
struct _ether {
	ether_header header;
	ether_body body;
};


/* Frame Header Structure */
typedef struct _frame_header frame_header;
struct _frame_header {
	u_char* arrival_time;
	u_int frame_len;
	u_int len;
};

/* Frame Body Structure */
typedef struct _frame_body frame_body;
struct _frame_body {
	ether ether_data;
};

/* Type Field */
typedef enum _frame_body_type frame_body_type;
enum _frame_body_type {
	ETHERNET = 1
};

/* Frame Structure */
typedef struct _frame frame;
struct _frame {
	frame_header header;
	frame_body body;
};