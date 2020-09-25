// See the file "COPYING" in the main distribution directory for copyright.

#include "Null.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::Null;

NullAnalyzer::NullAnalyzer()
	: zeek::packet_analysis::Analyzer("Null")
	{
	}

bool NullAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	int hdr_size = 4;

	if ( hdr_size >= len )
		{
		packet->Weird("null_analyzer_failed");
		return false;
		}

	uint32_t protocol = (data[3] << 24) + (data[2] << 16) + (data[1] << 8) + data[0];
	packet->hdr_size += hdr_size;

	return ForwardPacket(len - hdr_size, data + hdr_size, packet, protocol);
	}
