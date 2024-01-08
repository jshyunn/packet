#include "../header/atk_detector.h"

void d_atk(frame* frame_data)
{
	switch (frame_data->body.ether_data.body.ip_data.body_type)
	{
		case ICMP:
		{
			d_land(&frame_data->body.ether_data.body.ip_data.header);
			d_pod(&frame_data->header);
			break;
		}
		case TCP:
		{
			d_slow(&frame_data->body.ether_data.body.ip_data.body.tcp_data.header);
			break;
		}
		case UDP:
		{
			d_udp(&frame_data->header);
			break;
		}
	}
}

void d_land(ip_header* ip_hdr)
{
	if (!memcmp(&ip_hdr->src, &ip_hdr->dst, sizeof(ip_addr))) printf("#################################### Land Attack Occured!!!!!! ####################################\n");
}

void d_pod(frame_header* frame_hdr)
{
	if (frame_hdr->len == 1514) printf("#################################### Ping of Death Occured!!!!!! ####################################\n");
}

void d_udp(frame_header* frame_hdr)
{
	if (frame_hdr->len == 1514) printf("#################################### UDP Flood Occured!!!!!! ####################################\n");
}

void d_slow(tcp_header* tcp_hdr)
{
	if (tcp_hdr->win_size == 0) printf("#################################### Slow Read Occured!!!!!! ####################################\n");
}