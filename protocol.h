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


/* Ethernet Header Structure */
#pragma pack(push, 1)
typedef struct _ether_header ether_header;
struct _ether_header {
	mac_addr dst; /* Destination MAC address */
	mac_addr src; /* Source MAC address */
	u_short type; /* Type(1byte) & Length(1byte) */
};
#pragma pack(pop)

/* TYPE Field */
#define ETHERNET_IP 0x0800
#define ETHERNET_ARP 0x0806
#define ETHERNET_RARP 0x0835


/* ARP Header Structure */
typedef struct _arp_header arp_header;
struct _arp_header {
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

/* Protocol Field */
#define IP_ICMP 0x0001
#define IP_IGMP 0x0002
#define IP_TCP 0x0006
#define IP_UDP 0x0011


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
#define ICMP_ECHO_REP 0 /* Echo reply */
#define ICMP_ECHO_REQ 8 /* Echo request */


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
#define TCP_FTP 20
#define TCP_SSH 22
#define TCP_TELNET 23
#define TCP_SMTP 25
#define TCP_HTTP 80
#define TCP_POP3 110
#define TCP_IMAP4 143
#define TCP_HTTPS 443

/* UDP Header Structure */
typedef struct _udp_header udp_header;
struct _udp_header {
	u_short sport; /* Source port */
	u_short dport; /* Destination port */
	u_short tlen; /* Total length*/
	u_short checksum; /* Checksum */
};