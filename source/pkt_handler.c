#include <stdio.h>
#include <time.h>
<<<<<<< HEAD:pkt_handler.c
#include "pkt_handler.h"
#include "pkt_io.h"
#include "atk_detector.h"
=======
#include "../header/protocol.h"
#include "../header/pkt_handler.h"
#include "../header/pkt_io.h"
#include "../header/atk_detector.h"
>>>>>>> d919423 (파일 정리):source/pkt_handler.c

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* log_file, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	if (header->len < 14) return;

	frame frame_data = frame_handler(header, pkt_data);

	print_data(&frame_data);

	fprint_data((FILE*)log_file, &frame_data);

	d_atk(&frame_data);
}

frame frame_handler(const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	frame_header hdr = { 0 };
	struct tm* ltime;
	char timesec[9];
	char timeusec[8];
	char timestr[18];
	time_t local_tv_sec;

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timesec, sizeof timesec, "%H:%M:%S", ltime);
	snprintf(timeusec, sizeof timeusec, "%u", header->ts.tv_usec);
	snprintf(timestr, sizeof timestr, "%s.%s", timesec, timeusec);
	strcpy(hdr.arrival_time, timestr);
	hdr.frame_len = header->caplen;
	hdr.len = header->len;

	frame_body body = { 0 };
	body.ether_data = ether_handler(pkt_data);

	frame frame_data = { hdr, body };
	return frame_data;
}

ether ether_handler(const u_char* pkt_data)
{
	ether_header hdr = { 0 };
	ether_header* raw = (ether_header*)pkt_data;
	hdr.dst = raw->dst;
	hdr.src = raw->src;
	hdr.type = ntohs(raw->type);

	ether_body body = { 0 };
	ether_body_type type = ntohs(raw->type);

	pkt_data += sizeof(ether_header);
	switch (type)
	{
		case IPv4:
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

	ether ether_data = { hdr, body, type };
	return ether_data;
}

ip ip_handler(const u_char* pkt_data)
{
	ip_header hdr = { 0 };
	ip_header* raw = (ip_header*)pkt_data;
	hdr.ver_ihl = raw->ver_ihl;
	hdr.tos = raw->tos;
	hdr.tlen = ntohs(raw->tlen);
	hdr.id = ntohs(raw->id);
	hdr.off = ntohs(raw->off);
	hdr.ttl = raw->ttl;
	hdr.pro = raw->pro;
	hdr.checksum = ntohs(raw->checksum);
	hdr.src = raw->src;
	hdr.dst = raw->dst;

	ip_body body = { 0 };
	ip_body_type type = raw->pro;

	pkt_data += (int)(hdr.ver_ihl & 0x0f) * 4;
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

	ip ip_data = { hdr, body, type };
	return ip_data;
}

arp arp_handler(const u_char* pkt_data)
{
	arp pkt = { 0 };
	arp* raw = (arp*)pkt_data;
	pkt.hard = ntohs(raw->hard);
	pkt.pro = ntohs(raw->pro);
	pkt.hlen = raw->hlen;
	pkt.plen = raw->plen;
	pkt.op = ntohs(raw->op);
	pkt.sha = raw->sha;
	pkt.spa = raw->spa;
	pkt.dha = raw->dha;
	pkt.dpa = raw->dpa;
	return pkt;
}

icmp icmp_handler(const u_char* pkt_data)
{
	icmp_header hdr = { 0 };
	icmp_header* raw = (icmp_header*)pkt_data;
	hdr.type = raw->type;
	hdr.code = raw->code;
	hdr.checksum = ntohs(raw->checksum);

	pkt_data += sizeof(icmp_header);
	icmp icmp_data = { hdr, pkt_data };
	return icmp_data;
}

tcp tcp_handler(const u_char* pkt_data)
{
	tcp_header hdr = { 0 };
	tcp_header* raw = (tcp_header*)pkt_data;
	hdr.sport = (int)ntohs(raw->sport);
	hdr.dport = (int)ntohs(raw->dport);
	hdr.seq_num = ntohl(raw->seq_num);
	hdr.ack_num = ntohl(raw->ack_num);
	hdr.hlen_flags = ntohs(raw->hlen_flags);
	hdr.win_size = (int)ntohs(raw->win_size);
	hdr.checksum = ntohs(raw->checksum);
	hdr.urgent_ptr = ntohs(raw->urgent_ptr);

	pkt_data += ntohs(raw->hlen_flags & 0xf000) / 16 * 4;
	tcp tcp_data = { hdr, pkt_data };
	return tcp_data;
}

udp udp_handler(const u_char* pkt_data)
{
	udp_header hdr = { 0 };
	udp_header* raw = (udp_header*)pkt_data;
	hdr.sport = (int)ntohs(raw->sport);
	hdr.dport = (int)ntohs(raw->dport);
	hdr.tlen = (int)ntohs(raw->tlen);
	hdr.checksum = ntohs(raw->checksum);

	pkt_data += sizeof(udp_header);
	udp udp_data = { hdr, pkt_data };
	return udp_data;
}
