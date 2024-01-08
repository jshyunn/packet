#include <stdio.h>
#include <time.h>
#include "protocol.h"
#include "pkt_handler.h"

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	if (header->len < 14) return;

	printf("\n");
	frame_handler(save_file, header, pkt_data);
	printf("\n");
}

void frame_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	printf("=============================== Frame ================================\n");
	printf("%s,%.6d Frame Length: %d Capture Length: %d\n", timestr, header->ts.tv_usec, header->caplen, header->len);

	ether_handler(save_file, header, pkt_data);
}

void ether_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ether_header* pEther = (ether_header*)pkt_data;
	printf("============================== Ethernet ==============================\n");
	printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC: %02x:%02x:%02x:%02x:%02x:%02x Type: %04x\n",
		pEther->src.byte1, pEther->src.byte2, pEther->src.byte3, pEther->src.byte4, pEther->src.byte5, pEther->src.byte6,
		pEther->dst.byte1, pEther->dst.byte2, pEther->dst.byte3, pEther->dst.byte4, pEther->dst.byte5, pEther->dst.byte6,
		ntohs(pEther->type));

	switch (ntohs(pEther->type))
	{
		case ETHERNET_IP:
		{
			ip_handler(save_file, header, pkt_data + sizeof(ether_header));
			break;
		}
		case ETHERNET_ARP:
		{
			arp_handler(pkt_data + sizeof(ether_header));
			break;
		}
	}
}

void ip_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ip = (ip_header*)pkt_data;
	printf("=============================== IPv4 =================================\n");
	printf("Version: %d\n", (int)(ip->ver_ihl & 0xf0) / 16);
	printf("Internet Header Length: %d\n", (int)(ip->ver_ihl & 0x0f) * 4);
	printf("Type of Service: %02x\n", ip->tos);
	printf("Total Length: %d\n", ntohs(ip->tlen));
	printf("Identification: %04x\n", ntohs(ip->id));
	printf("Time to Live: %d\n", ip->ttl);
	printf("Protocol: %d\n", ip->pro);
	printf("Header Checksum : %04x\n", ntohs(ip->checksum));
	printf("SRC IP: %d.%d.%d.%d -> DST IP: %d.%d.%d.%d\n",
		ip->src.byte1, ip->src.byte2, ip->src.byte3, ip->src.byte4,
		ip->dst.byte1, ip->dst.byte2, ip->dst.byte3, ip->dst.byte4);

	if (!memcmp(&ip->src, &ip->dst, sizeof(ip_addr))) printf("#################################### Land Attack Occured!!!!!! ####################################\n");

	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	fprintf(save_file, "%s\t%d.%d.%d.%d\t%d.%d.%d.%d\t%s\t%d\n",
		timestr,
		ip->src.byte1, ip->src.byte2, ip->src.byte3, ip->src.byte4,
		ip->dst.byte1, ip->dst.byte2, ip->dst.byte3, ip->dst.byte4,
		convert_protocol(ip->pro),
		header->len);

	const u_char* de_pkt_data = (pkt_data + (int)(ip->ver_ihl & 0x0f) * 4);
	switch (ip->pro)
	{
		case IP_ICMP:
		{
			icmp_handler(header, de_pkt_data);
			break;
		}
		case IP_TCP:
		{
			tcp_handler(header, de_pkt_data);
			break;
		}
		case IP_UDP:
		{
			udp_handler(header, de_pkt_data);
			break;
		}
	}
}

void arp_handler(const u_char* pkt_data)
{
	arp_header* arp = (arp_header*)pkt_data;
	printf("================================ ARP =================================\n");
	printf("Hardware Type: %04x\n", ntohs(arp->hard));
	printf("Protocol Type: %04x\n", ntohs(arp->pro));
	printf("Hardware Size: %d\n", arp->hlen);
	printf("Protocol Size: %d\n", arp->plen);
	printf("Opcode: %04x\n", arp->op);
	printf("Sender MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp->sha.byte1, arp->sha.byte2, arp->sha.byte3, arp->sha.byte4, arp->sha.byte5, arp->sha.byte6);
	printf("Sender IP Address: %d.%d.%d.%d\n", arp->spa.byte1, arp->spa.byte2, arp->spa.byte3, arp->spa.byte4);
	printf("Target MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp->dha.byte1, arp->dha.byte2, arp->dha.byte3, arp->dha.byte4, arp->dha.byte5, arp->dha.byte6);
	printf("Target IP Address: %d.%d.%d.%d\n", arp->dpa.byte1, arp->dpa.byte2, arp->dpa.byte3, arp->dpa.byte4);
}


void icmp_handler(const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	icmp_header* icmp = (icmp_header*)pkt_data;
	printf("================================ ICMP ================================\n");
	printf("Type: %02x\n", icmp->type);
	printf("Code: %02x\n", icmp->code);
	printf("Checksum: %04x\n", ntohs(icmp->checksum));

	if (header->len == 1514) printf("#################################### Ping of Death Occured!!!!!! ####################################\n");

	data_handler(pkt_data + sizeof(icmp_header));
}


void tcp_handler(const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	tcp_header* tcp = (tcp_header*)pkt_data;
	printf("================================ TCP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", ntohs(tcp->sport), ntohs(tcp->dport));
	printf("Seq: %08x, Ack: %08x\n", ntohs(tcp->seq_num), ntohs(tcp->ack_num));
	printf("Header Len: %d\n", (int)(tcp->hlen_flags & 0x00ff) / 16 * 4);
	printf("Flags: %03x\n", ntohs(tcp->hlen_flags) & 0x0fff);
	printf("Window Size: %d\n", ntohs(tcp->win_size));
	printf("Checksum: %04x\n", ntohs(tcp->checksum));
	printf("Urgent Pointer: %04x\n", ntohs(tcp->urgent_ptr));

	if (tcp->win_size == 0) printf("#################################### Slow Read Occured!!!!!! ####################################\n");

	data_handler(pkt_data + (int)(tcp->hlen_flags & 0x00ff) / 16 * 4);
}

void udp_handler(const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	udp_header* udp = (udp_header*)pkt_data;
	printf("================================ UDP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", ntohs(udp->sport), ntohs(udp->dport));
	printf("Total Length: %d\n", ntohs(udp->tlen));
	printf("Checksum: %04x\n", ntohs(udp->checksum));

	if (header->len == 1514) printf("#################################### UDP Flood Occured!!!!!! ####################################\n");

	data_handler(pkt_data + sizeof(udp_header));
}

void data_handler(const u_char* pkt_data)
{
	printf("================================ DATA ================================\n");
	printf("%s\n", pkt_data);
}

char* convert_protocol(const u_char pro)
{
	char* protocol_name = "NULL";
	switch ((int)pro)
	{
		case (int)IP_ICMP:
		{
			protocol_name = "ICMP";
			break;
		}
		case (int)IP_TCP:
		{
			protocol_name = "TCP";
			break;
		}
		case (int)IP_UDP:
		{
			protocol_name = "UDP";
			break;
		}
	}
	return protocol_name;
}