#include <stdio.h>
#include <time.h>
#include "pkt_handler.h"

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	if (header->len < 14) return;

	printf("\n");
	frame frame_data = frame_handler(save_file, header, pkt_data);
	printf("\n");
}

frame frame_handler(u_char* save_file, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[16];
	char strBuffer[10];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S.", ltime);

	frame_header hdr = { strcat(timestr, ltoa(header->ts.tv_usec, strBuffer, 10)), header->caplen, header->len };
	//frame_body_type type;
	frame_body body;

	printf("=============================== Frame ================================\n");
	printf("%s Frame Length: %d Capture Length: %d\n", hdr.arrival_time, hdr.frame_len, hdr.len);

	

	body.ether_data = ether_handler(pkt_data);
	frame frame_data = { hdr, body };
	return frame_data;
}

ether ether_handler(const u_char* pkt_data)
{
	ether_header* hdr = (ether_header*)pkt_data;
	ether_body_type type = ntohs(hdr->type);
	ether_body body;

	printf("============================== Ethernet ==============================\n");
	printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC: %02x:%02x:%02x:%02x:%02x:%02x Type: %04x\n",
		hdr->src.byte1, hdr->src.byte2, hdr->src.byte3, hdr->src.byte4, hdr->src.byte5, hdr->src.byte6,
		hdr->dst.byte1, hdr->dst.byte2, hdr->dst.byte3, hdr->dst.byte4, hdr->dst.byte5, hdr->dst.byte6,
		ntohs(hdr->type));

	pkt_data += sizeof(ether_header);
	switch (type)
	{
		case IP:
		{
			body.ip_data = ip_handler(pkt_data);
			break;
		}
		case ARP:
		{
			body.arp_data = arp_handler(pkt_data);
			break;
		}
	}
	ether ether_data = { *hdr, body };
	return ether_data;
}

ip ip_handler(const u_char* pkt_data)
{
	ip_header* hdr = (ip_header*)pkt_data;
	ip_body_type type = hdr->pro;
	ip_body body;

	printf("=============================== IPv4 =================================\n");
	printf("Version: %d\n", (int)(hdr->ver_ihl & 0xf0) / 16);
	printf("Internet Header Length: %d\n", (int)(hdr->ver_ihl & 0x0f) * 4);
	printf("Type of Service: %02x\n", hdr->tos);
	printf("Total Length: %d\n", ntohs(hdr->tlen));
	printf("Identification: %04x\n", ntohs(hdr->id));
	printf("Time to Live: %d\n", hdr->ttl);
	printf("Protocol: %d\n", hdr->pro);
	printf("Header Checksum : %04x\n", ntohs(hdr->checksum));
	printf("SRC IP: %d.%d.%d.%d -> DST IP: %d.%d.%d.%d\n",
		hdr->src.byte1, hdr->src.byte2, hdr->src.byte3, hdr->src.byte4,
		hdr->dst.byte1, hdr->dst.byte2, hdr->dst.byte3, hdr->dst.byte4);

	//if (!memcmp(&ip->src, &ip->dst, sizeof(ip_addr))) printf("#################################### Land Attack Occured!!!!!! ####################################\n");

	/*struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;*/

	/* convert the timestamp to readable format */
	/*local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	fprintf(save_file, "%s\t%d.%d.%d.%d\t%d.%d.%d.%d\t%s\t%d\n",
		timestr,
		ip->src.byte1, ip->src.byte2, ip->src.byte3, ip->src.byte4,
		ip->dst.byte1, ip->dst.byte2, ip->dst.byte3, ip->dst.byte4,
		convert_protocol(ip->pro),
		header->len);*/

	pkt_data += (int)(hdr->ver_ihl & 0x0f) * 4;
	switch (type)
	{
		case ICMP:
		{
			body.icmp_data = icmp_handler(pkt_data);
			break;
		}
		case TCP:
		{
			body.tcp_data = tcp_handler(pkt_data);
			break;
		}
		case UDP:
		{
			body.udp_data = udp_handler(pkt_data);
			break;
		}
	}
	ip ip_data = { *hdr, body };
	return ip_data;
}

arp arp_handler(const u_char* pkt_data)
{
	arp* pkt = (arp*)pkt_data;
	printf("================================ ARP =================================\n");
	printf("Hardware Type: %04x\n", ntohs(pkt->hard));
	printf("Protocol Type: %04x\n", ntohs(pkt->pro));
	printf("Hardware Size: %d\n", pkt->hlen);
	printf("Protocol Size: %d\n", pkt->plen);
	printf("Opcode: %04x\n", pkt->op);
	printf("Sender MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		pkt->sha.byte1, pkt->sha.byte2, pkt->sha.byte3, pkt->sha.byte4, pkt->sha.byte5, pkt->sha.byte6);
	printf("Sender IP Address: %d.%d.%d.%d\n", pkt->spa.byte1, pkt->spa.byte2, pkt->spa.byte3, pkt->spa.byte4);
	printf("Target MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		pkt->dha.byte1, pkt->dha.byte2, pkt->dha.byte3, pkt->dha.byte4, pkt->dha.byte5, pkt->dha.byte6);
	printf("Target IP Address: %d.%d.%d.%d\n", pkt->dpa.byte1, pkt->dpa.byte2, pkt->dpa.byte3, pkt->dpa.byte4);
	return *pkt;
}

icmp icmp_handler(const u_char* pkt_data)
{
	icmp_header* hdr = (icmp_header*)pkt_data;
	printf("================================ ICMP ================================\n");
	printf("Type: %02x\n", hdr->type);
	printf("Code: %02x\n", hdr->code);
	printf("Checksum: %04x\n", ntohs(hdr->checksum));

	//if (header->len == 1514) printf("#################################### Ping of Death Occured!!!!!! ####################################\n");

	pkt_data += sizeof(icmp_header);
	icmp icmp_data = { *hdr, pkt_data };
	return icmp_data;
}

tcp tcp_handler(const u_char* pkt_data)
{
	tcp_header* hdr = (tcp_header*)pkt_data;
	printf("================================ TCP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", ntohs(hdr->sport), ntohs(hdr->dport));
	printf("Seq: %08x, Ack: %08x\n", ntohs(hdr->seq_num), ntohs(hdr->ack_num));
	printf("Header Len: %d\n", (int)(hdr->hlen_flags & 0x00ff) / 16 * 4);
	printf("Flags: %03x\n", ntohs(hdr->hlen_flags) & 0x0fff);
	printf("Window Size: %d\n", ntohs(hdr->win_size));
	printf("Checksum: %04x\n", ntohs(hdr->checksum));
	printf("Urgent Pointer: %04x\n", ntohs(hdr->urgent_ptr));

	//if (tcp->win_size == 0) printf("#################################### Slow Read Occured!!!!!! ####################################\n");

	pkt_data += (int)(hdr->hlen_flags & 0x00ff) / 16 * 4;
	tcp tcp_data = { *hdr, pkt_data };
	return tcp_data;
}

udp udp_handler(const u_char* pkt_data)
{
	udp_header* hdr = (udp_header*)pkt_data;
	printf("================================ UDP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", ntohs(hdr->sport), ntohs(hdr->dport));
	printf("Total Length: %d\n", ntohs(hdr->tlen));
	printf("Checksum: %04x\n", ntohs(hdr->checksum));

	//if (header->len == 1514) printf("#################################### UDP Flood Occured!!!!!! ####################################\n");

	pkt_data += sizeof(udp_header);
	udp udp_data = { *hdr, pkt_data };
	return udp_data;
}

void data_handler(const u_char* pkt_data)
{
	printf("================================ DATA ================================\n");
	printf("%s\n", pkt_data);
}

/*char* convert_protocol(const u_char pro)
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
}*/