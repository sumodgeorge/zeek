// See the file "COPYING" in the main distribution directory for copyright.

#include "IPv6.h"

using namespace zeek::packet_analysis::IPv6;

IPv6Analyzer::IPv6Analyzer()
	: zeek::packet_analysis::Analyzer("IPv6")
	{
	}

bool IPv6Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	packet->l3_proto = L3_IPV6;
	packet->session_analysis = true;

	// Session analysis doesn't expect the IP analyzer to have added it's header size to
	// the packet's header size, so we don't advance that value in this analyzer.

	// Leave packet analyzer land
	return true;
	}
