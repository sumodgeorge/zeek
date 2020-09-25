// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPoE.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::PPPoE;

PPPoEAnalyzer::PPPoEAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPoE")
	{
	}

bool PPPoEAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	int hdr_size = 8;

	if ( hdr_size >= len )
		{
		packet->Weird("truncated_pppoe_header");
		return false;
		}

	// Extract protocol identifier
	uint32_t protocol = (data[6] << 8u) + data[7];

	// Skip the PPPoE session and PPP header
	packet->hdr_size += hdr_size;
	return ForwardPacket(len - hdr_size, data + hdr_size, packet, protocol);
	}
