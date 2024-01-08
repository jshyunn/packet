#pragma once

#include "protocol.h"

void d_atk(frame*);
void d_land(ip_header*); // Land Attack
void d_pod(frame_header*); // Ping of Death
void d_udp(frame_header*); // UDP Flood Attack
void d_slow(tcp_header*); // Slow Read Attack