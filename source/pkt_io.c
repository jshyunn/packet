#include "../header/pkt_io.h"

void print_data(const frame* frame_data)
{
	printf("\n");
	print_l2_data(frame_data);
	print_l3_data(&frame_data->body.ether_data);
	print_l4_data(&frame_data->body.ether_data.body.ip_data);
	printf("\n");
}

void print_frame_data(const frame_header* frame_hdr)
{
	printf("=============================== Frame ================================\n");
	printf("Time: %s Frame Length: %d Capture Length: %d\n", frame_hdr->arrival_time, frame_hdr->frame_len, frame_hdr->len);
}

void print_ether_data(const ether_header* ether_hdr)
{
	printf("============================== Ethernet ==============================\n");
	printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC: %02x:%02x:%02x:%02x:%02x:%02x Type: 0x%04x\n",
		ether_hdr->src.byte1, ether_hdr->src.byte2, ether_hdr->src.byte3, ether_hdr->src.byte4, ether_hdr->src.byte5, ether_hdr->src.byte6,
		ether_hdr->dst.byte1, ether_hdr->dst.byte2, ether_hdr->dst.byte3, ether_hdr->dst.byte4, ether_hdr->dst.byte5, ether_hdr->dst.byte6,
		ether_hdr->type);
}

void print_ip_data(const ip_header* ip_hdr)
{
	printf("=============================== IPv4 =================================\n");
	printf("Version: %d\n", (int)(ip_hdr->ver_ihl & 0xf0) / 16);
	printf("Internet Header Length: %d\n", (int)(ip_hdr->ver_ihl & 0x0f) * 4);
	printf("Type of Service: 0x%02x\n", ip_hdr->tos);
	printf("Total Length: %d\n", ip_hdr->tlen);
	printf("Identification: 0x%04x\n", ip_hdr->id);
	printf("Time to Live: %d\n", ip_hdr->ttl);
	printf("Protocol: %d\n", ip_hdr->pro);
	printf("Header Checksum : 0x%04x\n", ip_hdr->checksum);
	printf("SRC IP: %d.%d.%d.%d -> DST IP: %d.%d.%d.%d\n",
		ip_hdr->src.byte1, ip_hdr->src.byte2, ip_hdr->src.byte3, ip_hdr->src.byte4,
		ip_hdr->dst.byte1, ip_hdr->dst.byte2, ip_hdr->dst.byte3, ip_hdr->dst.byte4);
}

void print_arp_data(const arp* arp_data)
{
	printf("================================ ARP =================================\n");
	printf("Hardware Type: 0x%04x\n", arp_data->hard);
	printf("Protocol Type: 0x%04x\n", arp_data->pro);
	printf("Hardware Size: %d\n", arp_data->hlen);
	printf("Protocol Size: %d\n", arp_data->plen);
	printf("Opcode: 0x%04x\n", arp_data->op);
	printf("Sender MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_data->sha.byte1, arp_data->sha.byte2, arp_data->sha.byte3, arp_data->sha.byte4, arp_data->sha.byte5, arp_data->sha.byte6);
	printf("Sender IP Address: %d.%d.%d.%d\n", arp_data->spa.byte1, arp_data->spa.byte2, arp_data->spa.byte3, arp_data->spa.byte4);
	printf("Target MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
		arp_data->dha.byte1, arp_data->dha.byte2, arp_data->dha.byte3, arp_data->dha.byte4, arp_data->dha.byte5, arp_data->dha.byte6);
	printf("Target IP Address: %d.%d.%d.%d\n", arp_data->dpa.byte1, arp_data->dpa.byte2, arp_data->dpa.byte3, arp_data->dpa.byte4);
}

void print_icmp_data(const icmp_header* icmp_hdr)
{
	printf("================================ ICMP ================================\n");
	printf("Type: 0x%02x\n", icmp_hdr->type);
	printf("Code: 0x%02x\n", icmp_hdr->code);
	printf("Checksum: 0x%04x\n", ntohs(icmp_hdr->checksum));
}

void print_tcp_data(const tcp_header* tcp_hdr)
{
	printf("================================ TCP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", tcp_hdr->sport, tcp_hdr->dport);
	printf("Seq: %u, Ack: %u\n", tcp_hdr->seq_num, tcp_hdr->ack_num);
	printf("Header Len: %d\n", (ntohs(tcp_hdr->hlen_flags & 0xf000) / 16 * 4));
	printf("Flags: 0x%03x\n", (tcp_hdr->hlen_flags & 0x0fff));
	printf("Window Size: %d\n", tcp_hdr->win_size);
	printf("Checksum: 0x%04x\n", tcp_hdr->checksum);
	printf("Urgent Pointer: 0x%04x\n", tcp_hdr->urgent_ptr);
}

void print_udp_data(const udp_header* udp_hdr)
{
	printf("================================ UDP =================================\n");
	printf("SRC Port: %d -> DST Port: %d\n", ntohs(udp_hdr->sport), ntohs(udp_hdr->dport));
	printf("Total Length: %d\n", ntohs(udp_hdr->tlen));
	printf("Checksum: 0x%04x\n", ntohs(udp_hdr->checksum));
}

void print_l2_data(const frame* frame_data)
{
	print_frame_data(&frame_data->header);
	print_ether_data(&frame_data->body.ether_data.header);
}

void print_l3_data(const ether* l2_data)
{
	if (l2_data->body_type < 0x0600)
	{
		printf("============================ IEEE 802.3 ==============================\n");
		return;
	}

	switch (l2_data->body_type)
	{
	case IPv4:
		print_ip_data(&l2_data->body.ip_data.header);
		break;
	case ARP:
		print_arp_data(&l2_data->body.arp_data);
		break;
	case IPv6:
		printf("=============================== IPv6 =================================\n");
		break;
	}
}

void print_l4_data(const ip* l3_data)
{
	switch (l3_data->body_type)
	{
	case ICMP:
		print_icmp_data(&l3_data->body.icmp_data.header);
		break;
	case TCP:
		print_tcp_data(&l3_data->body.tcp_data.header);
		break;
	case UDP:
		print_udp_data(&l3_data->body.udp_data.header);
		break;
	}
}

void fprint_data(FILE* log_file, const frame* frame_data)
{
	ip_addr src = frame_data->body.ether_data.body.ip_data.header.src;
	ip_addr dst = frame_data->body.ether_data.body.ip_data.header.dst;

	fprintf(log_file, "%s\t%d.%d.%d.%d\t%d.%d.%d.%d\t%x\t%d\n",
	frame_data->header.arrival_time,
	src.byte1, src.byte2, src.byte3, src.byte4,
	dst.byte1, dst.byte2, dst.byte3, dst.byte4,
	frame_data->body.ether_data.body.ip_data.body_type,
	frame_data->header.frame_len);
}