// See the file "COPYING" in the main distribution directory for copyright.

#include "PPPSerial.h"
#include "NetVar.h"

using namespace zeek::packet_analysis::PPPSerial;

PPPSerialAnalyzer::PPPSerialAnalyzer()
	: zeek::packet_analysis::Analyzer("PPPSerial")
	{
	}

bool PPPSerialAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	int hdr_size = 4;

	if ( hdr_size >= len )
		{
		packet->Weird("truncated_ppp_serial_header");
		return false;
		}

	// Extract protocol identifier
	uint32_t protocol = (data[2] << 8) + data[3];

	// skip link header
	packet->hdr_size += hdr_size;
	return ForwardPacket(len - hdr_size, data + hdr_size, packet, protocol);
	}
